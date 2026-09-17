import 'dotenv/config';
import mongoose from 'mongoose';
import { hashPassword } from 'better-auth/crypto';
import Flag from '../src/models/Flag.js';
import Profile from '../src/models/Profile.js';
import Ticket from '../src/models/Ticket.js';
import { FLAG_REGISTRY } from '../src/config/flags.js';
import crypto from 'crypto';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/deskwise';

async function seed() {
  try {
    console.log('Connecting to MongoDB for seeding...');
    await mongoose.connect(MONGODB_URI);
    const db = mongoose.connection.db;

    console.log('Clearing existing database collections...');
    await db.collection('user').deleteMany({});
    await db.collection('account').deleteMany({});
    await db.collection('session').deleteMany({});
    await Profile.deleteMany({});
    await Ticket.deleteMany({});
    await Flag.deleteMany({});

    console.log('Seeding Flag collection...');
    for (const [vulnId, info] of Object.entries(FLAG_REGISTRY)) {
      await Flag.create({
        vulnId,
        flag: info.flag,
        name: info.name,
        description: info.description,
      });
    }

    console.log('Creating users...');
    const hashedStandardPassword = await hashPassword('Password123!');
    const hashedWeakPassword = await hashPassword('password123');

    // 1. Admin User
    const adminUser = {
      _id: new mongoose.Types.ObjectId().toString(),
      name: 'Admin User',
      email: 'admin@deskwise.local',
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await db.collection('user').insertOne(adminUser);
    await db.collection('account').insertOne({
      userId: adminUser._id,
      accountId: adminUser.email,
      providerId: 'credential',
      password: hashedStandardPassword,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await Profile.create({
      userId: adminUser._id,
      role: 'admin',
      department: 'IT Security',
    });

    // 2. Agent User
    const agentUser = {
      _id: new mongoose.Types.ObjectId().toString(),
      name: 'Helpdesk Agent',
      email: 'agent@deskwise.local',
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await db.collection('user').insertOne(agentUser);
    await db.collection('account').insertOne({
      userId: agentUser._id,
      accountId: agentUser.email,
      providerId: 'credential',
      password: hashedStandardPassword,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await Profile.create({
      userId: agentUser._id,
      role: 'agent',
      department: 'Tier 1 Support',
    });

    // 3. Regular User (John Doe) — has A04 internalNotesMd5
    const regularUser = {
      _id: new mongoose.Types.ObjectId().toString(),
      name: 'John Doe',
      email: 'john@deskwise.local',
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await db.collection('user').insertOne(regularUser);
    await db.collection('account').insertOne({
      userId: regularUser._id,
      accountId: regularUser.email,
      providerId: 'credential',
      password: hashedStandardPassword,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    // Unsalted MD5 hash of flag for A04: CRYPTOFAIL{w34k_md5_n0_s4lt_ez_crack}
    const md5Hash = crypto
      .createHash('md5')
      .update('CRYPTOFAIL{w34k_md5_n0_s4lt_ez_crack}')
      .digest('hex');

    await Profile.create({
      userId: regularUser._id,
      role: 'user',
      department: 'Sales',
      internalNotesMd5: md5Hash,
    });

    // 4. Victim User for A06 Password Reset Target
    const victimUser = {
      _id: new mongoose.Types.ObjectId().toString(),
      name: 'Victim User',
      email: 'victim@deskwise.local',
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await db.collection('user').insertOne(victimUser);
    await db.collection('account').insertOne({
      userId: victimUser._id,
      accountId: victimUser.email,
      providerId: 'credential',
      password: hashedStandardPassword,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await Profile.create({
      userId: victimUser._id,
      role: 'user',
      department: 'Finance',
    });

    // 5. Weak Password User for A07 Brute Force Target
    const weakUser = {
      _id: new mongoose.Types.ObjectId().toString(),
      name: 'Weak Password User',
      email: 'weakuser@deskwise.local',
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    await db.collection('user').insertOne(weakUser);
    await db.collection('account').insertOne({
      userId: weakUser._id,
      accountId: weakUser.email,
      providerId: 'credential',
      password: hashedWeakPassword,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await Profile.create({
      userId: weakUser._id,
      role: 'user',
      department: 'Marketing',
    });

    console.log('Seeding Tickets...');
    // Public/Normal Tickets created by regular user
    await Ticket.create({
      title: 'Printer paper jam in 3rd floor office',
      description: 'The main printer on floor 3 is stuck on paper tray 2.',
      priority: 'low',
      status: 'open',
      createdBy: regularUser._id,
    });

    await Ticket.create({
      title: 'VPN disconnects every 10 minutes',
      description: 'Since yesterday my remote connection drops constantly.',
      priority: 'medium',
      status: 'in_progress',
      createdBy: regularUser._id,
    });

    // A01 IDOR / BOLA Target Ticket (created by admin, contains flag in description)
    const adminTicket = await Ticket.create({
      title: 'CONFIDENTIAL: Admin Root Credentials Backup',
      description:
        'DO NOT SHARE. Secret emergency flag: IDOR{y0u_acc3ssed_s0me0ne_elses_tick3t}',
      priority: 'urgent',
      status: 'open',
      createdBy: adminUser._id,
    });

    // A05 NoSQL Injection Target Ticket (contains flag in description)
    await Ticket.create({
      title: 'SECRET_FLAG_DATABASE_BACKUP_LOCATION',
      description:
        'Internal note: Flag for NoSQL injection is INJECT{m0ng0_0p3r4t0r_byp4ss}',
      priority: 'high',
      status: 'closed',
      createdBy: adminUser._id,
    });

    console.log('\n--- SEED COMPLETE ---');
    console.log('Admin account:      admin@deskwise.local / Password123!');
    console.log('Agent account:      agent@deskwise.local / Password123!');
    console.log('User account:       john@deskwise.local  / Password123!');
    console.log('Victim account:     victim@deskwise.local / Password123!');
    console.log('Weak account:       weakuser@deskwise.local / password123');
    console.log(`BOLA Ticket ID:     ${adminTicket._id}`);
    console.log('---------------------\n');

    process.exit(0);
  } catch (err) {
    console.error('Seeding failed:', err);
    process.exit(1);
  }
}

seed();
