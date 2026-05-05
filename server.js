const express    = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const neo4j      = require('neo4j-driver');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

// ═══════════════════════════════════════════════════════════
//   MONGODB  — songs & votes (your existing setup, unchanged)
// ═══════════════════════════════════════════════════════════
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/playlistDB';
let songsCollection;
let votesCollection;

async function connectMongo() {
    try {
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        console.log('✅ MongoDB connected');
        const db = client.db('playlistDB');
        songsCollection = db.collection('songs');
        votesCollection = db.collection('votes');
        await songsCollection.createIndex({ title: 1, artist: 1, event: 1 });
        await songsCollection.createIndex({ votes: -1 });
        await songsCollection.createIndex({ event: 1 });
        await votesCollection.createIndex({ userId: 1, songId: 1 }, { unique: true });
        console.log('✅ MongoDB indexes ready');
    } catch (err) {
        console.error('❌ MongoDB error:', err.message);
        process.exit(1);
    }
}

// ═══════════════════════════════════════════════════════════
//   NEO4J  — users (students & organizers) + events
// ═══════════════════════════════════════════════════════════
const neo4jDriver = neo4j.driver(
    process.env.NEO4J_URI      || 'bolt://localhost:7687',
    neo4j.auth.basic(
        process.env.NEO4J_USER     || 'neo4j',
        process.env.NEO4J_PASSWORD || 'password123'
    )
);

async function connectNeo4j() {
    const session = neo4jDriver.session();
    try {
        await session.run('RETURN 1');
        console.log('✅ Neo4j connected');

        // Create constraints once — safe to repeat
        const constraints = [
            `CREATE CONSTRAINT IF NOT EXISTS FOR (s:Student)  REQUIRE s.roll  IS UNIQUE`,
            `CREATE CONSTRAINT IF NOT EXISTS FOR (o:Organizer) REQUIRE o.roll IS UNIQUE`,
            `CREATE CONSTRAINT IF NOT EXISTS FOR (s:Student)  REQUIRE s.email IS UNIQUE`,
            `CREATE CONSTRAINT IF NOT EXISTS FOR (o:Organizer) REQUIRE o.email IS UNIQUE`,
            `CREATE CONSTRAINT IF NOT EXISTS FOR (e:Event)    REQUIRE e.name  IS UNIQUE`,
        ];
        for (const c of constraints) {
            try { await session.run(c); } catch { /* already exists */ }
        }

        // Seed the 8 default events into Neo4j on first run
        const defaultEvents = [
            { name:'Hostel Day',   icon:'🏠', description:'Annual hostel celebration' },
            { name:'Sem Fest',     icon:'📚', description:'Semester festival vibes' },
            { name:'Freshers Day', icon:'🎓', description:'Welcome new students' },
            { name:'Intrams',      icon:'🏆', description:'Sports tournament' },
            { name:'Kriya',        icon:'🔬', description:'Technical symposium' },
            { name:'Shrishti',     icon:'🎨', description:'Arts & crafts fest' },
            { name:'Infinitum',    icon:'♾️',  description:'Annual techno-cultural fest' },
            { name:'Culturals',    icon:'🎭', description:'Cultural events showcase' },
        ];
        for (const e of defaultEvents) {
            await session.run(
                `MERGE (e:Event {name:$name})
                 ON CREATE SET e.icon=$icon, e.description=$description, e.createdAt=datetime()`,
                e
            );
        }
        console.log('✅ Neo4j events seeded');
    } catch (err) {
        console.error('❌ Neo4j error:', err.message);
        console.error('   → Make sure Neo4j Desktop is running');
        console.error('   → Make sure .env NEO4J_PASSWORD is correct');
        process.exit(1);
    } finally {
        await session.close();
    }
}

// JWT middleware
function verifyToken(req, res, next) {
    const header = req.headers['authorization'];
    const token  = header && header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided.' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET || 'playlistcollab_secret');
        next();
    } catch {
        res.status(403).json({ error: 'Invalid or expired token.' });
    }
}

function organizerOnly(req, res, next) {
    if (req.user.role !== 'organizer')
        return res.status(403).json({ error: 'Organizer access only.' });
    next();
}

// ═══════════════════════════════════════════════════════════
//   AUTH ROUTES  →  stored in Neo4j
// ═══════════════════════════════════════════════════════════

// POST /api/auth/register
// Called by auth.html Sign Up
// Body: { name, roll, studentId OR organizerId, department, email, password, role }
app.post('/api/auth/register', async (req, res) => {
    const session = neo4jDriver.session();
    try {
        const { name, roll, studentId, organizerId, department, email, password, role } = req.body;

        // Validate
        if (!name || !roll || !department || !email || !password || !role)
            return res.status(400).json({ error: 'All fields are required.' });
        if (!['student', 'organizer'].includes(role))
            return res.status(400).json({ error: 'Role must be student or organizer.' });
        if (role === 'student'   && !studentId)   return res.status(400).json({ error: 'Student ID is required.' });
        if (role === 'organizer' && !organizerId) return res.status(400).json({ error: 'Organizer ID is required.' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

        const label   = role === 'student' ? 'Student' : 'Organizer';
        const idField = role === 'student' ? 'studentId' : 'organizerId';
        const idValue = role === 'student' ? studentId  : organizerId;

        // Check for duplicates (same roll or email)
        const dup = await session.run(
            `MATCH (u:${label}) WHERE u.roll=$roll OR u.email=$email RETURN u LIMIT 1`,
            { roll, email }
        );
        if (dup.records.length)
            return res.status(409).json({ error: 'Account already exists with this Roll No or Email.' });

        // Hash password
        const passwordHash = await bcrypt.hash(password, 12);
        const uid = `${role}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;

        // CREATE node → stored in Neo4j
        const result = await session.run(
            `CREATE (u:${label} {
                id:           $uid,
                name:         $name,
                roll:         $roll,
                ${idField}:   $idValue,
                department:   $department,
                email:        $email,
                passwordHash: $passwordHash,
                role:         $role,
                createdAt:    datetime()
            }) RETURN u`,
            { uid, name, roll, idValue, department, email, passwordHash, role }
        );

        const u = result.records[0].get('u').properties;
        console.log(`✅ Registered ${role}: ${name} (${roll})`);

        res.status(201).json({
            message: 'Account created successfully!',
            user: { id: u.id, name: u.name, roll: u.roll, department: u.department, email: u.email, role: u.role }
        });

    } catch (err) {
        console.error('Register error:', err);
        res.status(500).json({ error: 'Server error during registration.' });
    } finally {
        await session.close();
    }
});

// POST /api/auth/login
// Called by auth.html Log In
// Body: { roll, password, role }
app.post('/api/auth/login', async (req, res) => {
    const session = neo4jDriver.session();
    try {
        const { roll, password, role } = req.body;

        if (!roll || !password || !role)
            return res.status(400).json({ error: 'ID, password and role are required.' });
        if (!['student', 'organizer'].includes(role))
            return res.status(400).json({ error: 'Invalid role.' });

        const label   = role === 'student' ? 'Student' : 'Organizer';
        const idField = role === 'student' ? 'studentId' : 'organizerId';

        // Find by roll number OR studentId/organizerId — whichever matches
        const result = await session.run(
            `MATCH (u:${label}) WHERE u.roll=$roll OR u.${idField}=$roll RETURN u LIMIT 1`,
            { roll }
        );

        if (!result.records.length)
            return res.status(401).json({ error: 'Invalid ID or password.' });

        const u     = result.records[0].get('u').properties;
        const match = await bcrypt.compare(password, u.passwordHash);
        if (!match)
            return res.status(401).json({ error: 'Invalid ID or password.' });

        // Generate JWT
        const token = jwt.sign(
            { id: u.id, role: u.role, name: u.name },
            process.env.JWT_SECRET || 'playlistcollab_secret',
            { expiresIn: '24h' }
        );

        console.log(`✅ Login: ${u.name} (${u.role})`);

        res.json({
            message: 'Login successful!',
            token,
            user: { id: u.id, name: u.name, roll: u.roll, department: u.department, email: u.email, role: u.role }
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error during login.' });
    } finally {
        await session.close();
    }
});

// ═══════════════════════════════════════════════════════════
//   EVENTS ROUTES  →  stored in Neo4j
// ═══════════════════════════════════════════════════════════

// GET /api/events  — used by events.html to show all events
app.get('/api/events', async (req, res) => {
    const session = neo4jDriver.session();
    try {
        const result = await session.run(`MATCH (e:Event) RETURN e ORDER BY e.createdAt ASC`);
        const events = result.records.map(r => {
            const e = r.get('e').properties;
            return { name: e.name, icon: e.icon || '🎵', description: e.description || '' };
        });
        res.json(events);
    } catch (err) {
        console.error('Get events error:', err);
        res.status(500).json({ error: 'Failed to fetch events.' });
    } finally {
        await session.close();
    }
});

// GET /api/events/my  — events created by THIS organizer (for add_event page list)
app.get('/api/events/my', verifyToken, organizerOnly, async (req, res) => {
    const session = neo4jDriver.session();
    try {
        const result = await session.run(
            `MATCH (o:Organizer {id:$orgId})-[:CREATED]->(e:Event)
             RETURN e ORDER BY e.createdAt DESC`,
            { orgId: req.user.id }
        );
        const events = result.records.map(r => {
            const e = r.get('e').properties;
            return { name: e.name, icon: e.icon || '🎵', description: e.description || '' };
        });
        res.json(events);
    } catch (err) {
        console.error('Get my events error:', err);
        res.status(500).json({ error: 'Failed to fetch your events.' });
    } finally {
        await session.close();
    }
});

// POST /api/events  — organizer adds a new event → saved to Neo4j
app.post('/api/events', verifyToken, organizerOnly, async (req, res) => {
    const session = neo4jDriver.session();
    try {
        const { name, icon, description } = req.body;
        if (!name || !description)
            return res.status(400).json({ error: 'Name and description are required.' });

        const dup = await session.run(`MATCH (e:Event {name:$name}) RETURN e LIMIT 1`, { name });
        if (dup.records.length)
            return res.status(409).json({ error: `Event "${name}" already exists.` });

        const result = await session.run(
            `MATCH (o:Organizer {id:$orgId})
             CREATE (e:Event { name:$name, icon:$icon, description:$description, createdAt:datetime() })
             CREATE (o)-[:CREATED]->(e)
             RETURN e`,
            { orgId: req.user.id, name, icon: icon || '🎵', description }
        );

        const e = result.records[0].get('e').properties;
        console.log(`✅ Event created: ${name}`);
        res.status(201).json({ message: `"${name}" published!`, event: { name: e.name, icon: e.icon, description: e.description } });

    } catch (err) {
        console.error('Create event error:', err);
        res.status(500).json({ error: 'Failed to create event.' });
    } finally {
        await session.close();
    }
});

// GET /api/events/:eventName/top10
// Fetches top 10 from MongoDB, saves snapshot to Neo4j
app.get('/api/events/:eventName/top10', verifyToken, organizerOnly, async (req, res) => {
    const session = neo4jDriver.session();
    try {
        const { eventName } = req.params;

        const songs = await songsCollection
            .find({ event: eventName })
            .sort({ votes: -1 })
            .limit(10)
            .toArray();

        const top10 = songs.map((s, i) => ({
            rank:   i + 1,
            id:     s._id.toString(),
            title:  s.title,
            artist: s.artist,
            votes:  s.votes || 0
        }));

        // Save Top10 snapshot into Neo4j so it's permanently stored
        if (top10.length > 0) {
            await session.run(
                `MATCH (e:Event {name:$eventName})
                 MERGE (t:Top10Snapshot {eventName:$eventName})
                 SET t.songs=$songsJson, t.updatedAt=datetime()
                 MERGE (t)-[:SNAPSHOT_OF]->(e)`,
                { eventName, songsJson: JSON.stringify(top10) }
            );
            console.log(`✅ Top10 snapshot saved to Neo4j for: ${eventName}`);
        }

        res.json(top10);
    } catch (err) {
        console.error('Top10 error:', err);
        res.status(500).json({ error: 'Failed to fetch top 10.' });
    } finally {
        await session.close();
    }
});

// ═══════════════════════════════════════════════════════════
//   SONGS & VOTES ROUTES  →  stored in MongoDB (unchanged)
// ═══════════════════════════════════════════════════════════

const sanitizeSong = (song) => {
    if (!song || typeof song !== 'object') return null;
    return {
        _id:       song._id,
        title:     song.title  || 'Unknown',
        artist:    song.artist || 'Unknown',
        votes:     typeof song.votes === 'number' ? song.votes : 0,
        event:     song.event  || '',
        createdAt: song.createdAt || new Date(),
    };
};

app.get('/api/songs', async (req, res) => {
    try {
        const songs = await songsCollection.find({}).sort({ votes: -1 }).toArray();
        res.json(songs.map(sanitizeSong).filter(Boolean));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/songs/event/:eventName', async (req, res) => {
    try {
        const eventName = decodeURIComponent(req.params.eventName);
        const songs = await songsCollection.find({ event: eventName }).sort({ votes: -1 }).toArray();
        res.json(songs.map(sanitizeSong).filter(Boolean));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/songs/event/:eventName/top/:limit', async (req, res) => {
    try {
        const eventName = decodeURIComponent(req.params.eventName);
        const limit     = parseInt(req.params.limit) || 20;
        const songs = await songsCollection.find({ event: eventName }).sort({ votes: -1 }).limit(limit).toArray();
        res.json(songs.map(sanitizeSong).filter(Boolean));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/songs/:id', async (req, res) => {
    try {
        const song = await songsCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!song) return res.status(404).json({ error: 'Song not found' });
        res.json(sanitizeSong(song));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/songs', async (req, res) => {
    try {
        const { title, artist, event } = req.body;
        if (!title || !artist || !event)
            return res.status(400).json({ error: 'Title, artist, and event are required' });

        const duplicate = await songsCollection.findOne({
            title:  { $regex: new RegExp(`^${title}$`,  'i') },
            artist: { $regex: new RegExp(`^${artist}$`, 'i') },
            event
        });
        if (duplicate)
            return res.status(400).json({ error: 'This song has already been suggested!' });

        const result      = await songsCollection.insertOne({ title, artist, votes: 0, event, createdAt: new Date() });
        const insertedSong = await songsCollection.findOne({ _id: result.insertedId });
        res.status(201).json(sanitizeSong(insertedSong));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/songs/:id/vote', async (req, res) => {
    try {
        const { userId, event } = req.body;
        const songId = req.params.id;

        if (!userId || !event)
            return res.status(400).json({ error: 'userId and event are required' });
        if (!ObjectId.isValid(songId))
            return res.status(400).json({ error: 'Invalid song ID' });

        const existingVote = await votesCollection.findOne({ userId, songId });
        if (existingVote)
            return res.status(400).json({ error: 'You have already voted for this song!' });

        const songBefore = await songsCollection.findOne({ _id: new ObjectId(songId) });
        if (!songBefore) return res.status(404).json({ error: 'Song not found' });

        try {
            await votesCollection.insertOne({ userId, songId, event, votedAt: new Date() });
        } catch (e) {
            if (e.code === 11000) return res.status(400).json({ error: 'You have already voted for this song!' });
            throw e;
        }

        const updateResult = await songsCollection.findOneAndUpdate(
            { _id: new ObjectId(songId) },
            { $inc: { votes: 1 } },
            { returnDocument: 'after' }
        );

        let updatedSong = updateResult?.value || (updateResult?._id ? updateResult : null);
        if (!updatedSong) updatedSong = await songsCollection.findOne({ _id: new ObjectId(songId) });

        res.json(sanitizeSong(updatedSong) || {
            _id: songId, title: songBefore.title, artist: songBefore.artist,
            votes: (songBefore.votes || 0) + 1, event
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/songs/:id', async (req, res) => {
    try {
        const result = await songsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (!result.deletedCount) return res.status(404).json({ error: 'Song not found' });
        await votesCollection.deleteMany({ songId: req.params.id });
        res.json({ message: 'Song deleted successfully' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/votes/user/:userId/event/:event', async (req, res) => {
    try {
        const { userId } = req.params;
        const event = decodeURIComponent(req.params.event);
        const votes = await votesCollection.find({ userId, event }).toArray();
        res.json(votes.map(v => v.songId));
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/health', (_req, res) => res.json({ status: 'OK', time: new Date() }));

// ═══════════════════════════════════════════════════════════
//   START BOTH DATABASES
// ═══════════════════════════════════════════════════════════
async function start() {
    await connectMongo();   // MongoDB for songs & votes
    await connectNeo4j();   // Neo4j for users & events
    app.listen(PORT, () => {
        console.log(`\n🚀 Server → http://localhost:${PORT}`);
        console.log('\n📌 What goes where:');
        console.log('  Neo4j   → Students, Organizers, Events, Top10 snapshots');
        console.log('  MongoDB → Songs, Votes\n');
    });
}
start();