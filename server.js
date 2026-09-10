// backend/server.js
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, '.env') });

import express from 'express';
import cors from 'cors';
// import multer from 'multer'; // TODO: Install multer with npm install multer
import { createClient } from '@supabase/supabase-js';

// Now everything else...

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
const allowedOrigins = new Set([
  process.env.FRONTEND_URL,
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://192.168.92.1:5173',
  'http://172.30.112.1:5173',
  'https://careconnect-frontend-ashy.vercel.app',
].filter(Boolean));

const isAllowedDevelopmentOrigin = (origin) => {
  if (process.env.NODE_ENV !== 'development' || !origin) return false;

  try {
    const { hostname } = new URL(origin);
    return ['localhost', '127.0.0.1', '192.168.92.1', '172.30.112.1'].includes(hostname);
  } catch {
    return false;
  }
};

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.has(origin) || isAllowedDevelopmentOrigin(origin)) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true
}));
app.use(express.json());

// Configure multer for file uploads
// const storage = multer.memoryStorage();
// const upload = multer({
//   storage: storage,
//   limits: {
//     fileSize: 5 * 1024 * 1024, // 5MB limit
//   },
//   fileFilter: (req, file, cb) => {
//     const allowedTypes = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png'];
//     if (allowedTypes.includes(file.mimetype)) {
//       cb(null, true);
//     } else {
//       cb(new Error('Invalid file type. Only PDF, JPG, and PNG are allowed.'));
//     }
//   }
// });

// Initialize Supabase with SERVICE_ROLE_KEY for admin operations
export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

console.log('🔗 Supabase connected');
console.log(`🌐 CORS enabled for: ${[...allowedOrigins].join(', ')}`);

const createAdminToken = (admin) => jwt.sign(
  { sub: admin.id, role: 'admin', type: 'careconnect_admin' },
  process.env.JWT_SECRET,
  { expiresIn: '12h' }
);

const getApplicationToken = (token) => {
  if (!process.env.JWT_SECRET) return null;
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
};

// ============================================
// AUTHORIZATION MIDDLEWARE
// ============================================

// Verify user authentication (generic for all protected routes)
const requireAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    const token = authHeader.substring(7);

    const applicationUser = getApplicationToken(token);
    if (applicationUser?.type === 'careconnect_admin') {
      req.user = { id: applicationUser.sub, role: 'admin' };
      req.userId = applicationUser.sub;
      return next();
    }
    
    // Verify token with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Attach user info to request
    req.user = user;
    req.userId = user.id;
    next();
  } catch (error) {
    console.error('❌ Authorization error:', error.message);
    res.status(500).json({ error: 'Authorization check failed' });
  }
};

// Verify admin authorization
const requireAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    const token = authHeader.substring(7);

    const applicationUser = getApplicationToken(token);
    if (applicationUser?.type === 'careconnect_admin') {
      const { data: adminData, error: adminError } = await supabase
        .from('users')
        .select('id, email, full_name, role, profile_image_url')
        .eq('id', applicationUser.sub)
        .eq('role', 'admin')
        .single();

      if (adminError || !adminData) {
        return res.status(403).json({ error: 'Admin access required' });
      }
      req.adminUser = adminData;
      req.adminId = adminData.id;
      return next();
    }
    
    // Verify token with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Check if user is admin
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('role')
      .eq('id', user.id)
      .single();

    if (userError || !userData || userData.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Admin access required' });
    }

    // Attach user info to request
    req.adminUser = user;
    req.adminId = user.id;
    next();
  } catch (error) {
    console.error('❌ Authorization error:', error.message);
    res.status(500).json({ error: 'Authorization check failed' });
  }
};

const isDoctorProfileComplete = (doctor) => Boolean(
  doctor &&
  doctor.specialty &&
  doctor.specialty !== 'Not specified' &&
  doctor.hospital_name &&
  doctor.hospital_name !== 'Not specified' &&
  Number(doctor.years_experience) > 0 &&
  doctor.medical_license &&
  doctor.medical_license !== 'Pending' &&
  Number(doctor.hourly_rate) > 0
);

const getAllowedDoctorLicensePrefixes = () => (process.env.ACCEPTABLE_DOCTOR_LICENSE_NUMBERS || '')
  .split(',')
  .map(license => license.trim().toLowerCase().replace(/\d+$/, ''))
  .filter(Boolean);

const isAcceptableDoctorLicense = (license) => {
  const normalizedLicense = String(license || '').trim().toLowerCase();
  const prefixes = getAllowedDoctorLicensePrefixes();
  return prefixes.some(prefix => (
    normalizedLicense.startsWith(prefix) &&
    /^\d+$/.test(normalizedLicense.slice(prefix.length))
  ));
};

const getUsersByIds = async (userIds) => {
  const ids = [...new Set(userIds.filter(Boolean))];
  if (ids.length === 0) return new Map();

  const { data, error } = await supabase
    .from('users')
    .select('id, full_name, email, profile_image_url, phone')
    .in('id', ids);

  if (error) throw error;
  return new Map((data || []).map(user => [user.id, user]));
};

const insertNotification = async ({ userId, type, title, message, data = {} }) => {
  const { error } = await supabase.from('notifications').insert({
    user_id: userId,
    type,
    title,
    message,
    data,
    is_read: false,
  });

  if (error) throw error;
};

// ============================================
// HEALTH CHECK
// ============================================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'Backend is running ✅',
    timestamp: new Date().toISOString(),
    port: PORT
  });
});

// ============================================
// AUTH ROUTES
// ============================================

// Validate session and return user data with role
app.post('/api/auth/validate', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }

    const token = authHeader.substring(7);

    const applicationUser = getApplicationToken(token);
    if (applicationUser?.type === 'careconnect_admin') {
      const { data: adminData, error: adminError } = await supabase
        .from('users')
        .select('*')
        .eq('id', applicationUser.sub)
        .eq('role', 'admin')
        .single();

      if (adminError || !adminData) {
        return res.status(401).json({ error: 'Invalid admin session' });
      }
      return res.json({
        success: true,
        user: adminData,
        role: 'admin',
        profile: adminData,
        profileComplete: true,
      });
    }
    
    // Verify token with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Get user profile from database
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('*')
      .eq('id', user.id)
      .single();

    if (userError || !userData) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    // Get role-specific profile
    let doctorProfile = null;
    let profileComplete = true;

    if (userData.role === 'doctor') {
      const { data: doctorData } = await supabase
        .from('doctors')
        .select('*')
        .eq('user_id', user.id)
        .single();
      
      if (doctorData) {
        doctorProfile = doctorData;
        profileComplete = isDoctorProfileComplete(doctorData);
      }
    }

    res.json({
      user: {
        id: userData.id,
        email: userData.email,
        full_name: userData.full_name,
        role: userData.role,
        profile_image_url: userData.profile_image_url,
        phone: userData.phone,
      },
      doctorProfile,
      profileComplete,
    });
  } catch (error) {
    console.error('❌ Validate session error:', error.message);
    res.status(500).json({ error: 'Session validation failed' });
  }
});

// Sign Up
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, fullName, role, verificationCode } = req.body;

    // Validate input
    if (!email || !password || !fullName || !role) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Admin verification
    if (role === 'admin') {
      const adminPasskey = process.env.ADMIN_PASSKEY;

      if (!adminPasskey || verificationCode !== adminPasskey) {
        return res.status(403).json({ 
          error: 'A valid admin passkey is required for admin registration'
        });
      }
    }

    // Create Supabase auth user (uses auth.users table)
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
    });

    if (authError) throw authError;

    const userId = authData.user.id;

    // Check if user profile already exists in custom users table
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('id', userId)
      .single();

    let userError;
    
    if (existingUser) {
      // User profile already exists, update it instead
      const { error: updateError } = await supabase
        .from('users')
        .update({
          email,
          role,
          full_name: fullName,
        })
        .eq('id', userId);
      userError = updateError;
    } else {
      // Create new user profile in custom users table
      const { error: insertError } = await supabase
        .from('users')
        .insert({
          id: userId,  // Link to auth.users.id
          email,
          role,
          full_name: fullName,
          // password_hash is handled by Supabase auth
        });
      userError = insertError;
    }

    if (userError) {
      // If profile creation fails, delete the auth user to prevent orphaned accounts
      await supabase.auth.admin.deleteUser(userId);
      throw userError;
    }

    // Create role-specific profile
    if (role === 'doctor') {
      // Check if doctor profile already exists
      const { data: existingDoctor, error: doctorCheckError } = await supabase
        .from('doctors')
        .select('id')
        .eq('user_id', userId)
        .single();
      
      if (!existingDoctor) {
        const { error: doctorError } = await supabase
          .from('doctors')
          .insert({ 
            user_id: userId,
            specialty: 'Not specified',
            years_experience: 0,
            hospital_name: 'Not specified',
            medical_license: 'Pending',
            hourly_rate: 0,
            bio: '',
            verification_status: 'pending'
          });
        if (doctorError) throw doctorError;
      }
    } else if (role === 'patient') {
      // Check if patient profile already exists
      const { data: existingPatient, error: patientCheckError } = await supabase
        .from('patients')
        .select('id')
        .eq('user_id', userId)
        .single();
      
      if (!existingPatient) {
        const { error: patientError } = await supabase
          .from('patients')
          .insert({ user_id: userId });
        if (patientError) throw patientError;
      }
    }

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      userId,
      email,
      role
    });
  } catch (error) {
    console.error('❌ Signup error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, role: requestedRole = 'patient' } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Sign in with Supabase auth
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw error;

    // Get user role from your custom users table
    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('role, full_name, profile_image_url')
      .eq('id', data.user.id)
      .single();

    if (userError) throw userError;

    const userRole = userData.role;

    // If doctor, fetch doctor profile to check if complete
    let doctorProfile = null;
    let profileComplete = true;
    
    if (userRole === 'doctor') {
      const { data: doctorData, error: doctorError } = await supabase
        .from('doctors')
        .select('*')
        .eq('user_id', data.user.id)
        .single();
      
      if (doctorError) {
        console.error('Error fetching doctor profile:', doctorError);
      } else {
        doctorProfile = doctorData;
        profileComplete = isDoctorProfileComplete(doctorData);
      }
    }

    res.json({
      success: true,
      user: data.user,
      role: userRole,
      profile: userData,
      doctorProfile,
      profileComplete,
      session: data.session,
    });
  } catch (error) {
    console.error('❌ Login error:', error.message);
    res.status(401).json({ error: error.message });
  }
});

// Admin login uses only the configured passkey and the single admin database account.
app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const { passkey } = req.body;
    const configuredPasskey = process.env.ADMIN_PASSKEY;

    if (!configuredPasskey) {
      return res.status(503).json({ error: 'Admin authentication is not configured' });
    }

    const supplied = Buffer.from(String(passkey || '').trim());
    const expected = Buffer.from(configuredPasskey);
    const isValidPasskey = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
    if (!isValidPasskey) {
      return res.status(401).json({ error: 'Invalid admin passkey' });
    }

    const { data: adminUsers, error: adminLookupError } = await supabase
      .from('users')
      .select('id, email, full_name, role, profile_image_url')
      .eq('role', 'admin');

    if (adminLookupError) throw adminLookupError;
    if (adminUsers?.length !== 1 || !adminUsers[0]?.email) {
      return res.status(503).json({ error: 'Admin account is not configured correctly' });
    }

    const adminUser = adminUsers[0];
    const accessToken = createAdminToken(adminUser);

    res.json({
      success: true,
      user: adminUser,
      role: 'admin',
      profile: adminUser,
      profileComplete: true,
      session: { access_token: accessToken },
    });
  } catch (error) {
    console.error('❌ Admin login error:', error.message);
    res.status(401).json({ error: 'Admin authentication failed' });
  }
});

// OAuth Callback
app.post('/api/auth/oauth/callback', async (req, res) => {
  try {
    const { email, fullName, role: requestedRole, accessToken } = req.body;

    if (!email || !accessToken) {
      return res.status(400).json({ error: 'Email and access token required' });
    }

    // Verify the access token with Supabase
    const { data: { user }, error: verifyError } = await supabase.auth.getUser(accessToken);

    if (verifyError || !user) {
      return res.status(401).json({ error: 'Invalid access token' });
    }

    // Check if user exists in custom users table
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('*')
      .eq('id', user.id)
      .maybeSingle();

    let userData;
    let doctorProfile = null;
    let profileComplete = true;

    if (existingUser) {
      // User exists, return their data
      userData = existingUser;

      // If doctor, fetch profile
      if (existingUser.role === 'doctor') {
        const { data: docData } = await supabase
          .from('doctors')
          .select('*')
          .eq('user_id', user.id)
          .maybeSingle();

        if (docData) {
          doctorProfile = docData;
          profileComplete = isDoctorProfileComplete(docData);
        }
      }
    } else {
      // New users are assigned by trusted server configuration, never by the browser.
      const finalRole = ['patient', 'doctor'].includes(requestedRole)
        ? requestedRole
        : 'patient';

      const profile = {
        id: user.id,
        email: user.email,
        role: finalRole,
        full_name: fullName || user.email.split('@')[0],
      };

      // OAuth callbacks can be delivered more than once. Insert once, then
      // re-read the row if another callback won the unique-key race.
      const { error: insertError } = await supabase.from('users').insert(profile);

      if (insertError) {
        const isDuplicate = insertError.code === '23505' || insertError.message?.includes('users_pkey');
        if (!isDuplicate) throw insertError;

        const { data: concurrentUser, error: concurrentUserError } = await supabase
          .from('users')
          .select('*')
          .eq('id', user.id)
          .maybeSingle();

        if (concurrentUserError) throw concurrentUserError;
        userData = concurrentUser || profile;
      } else {
        userData = profile;
      }

      // Create role-specific profile
      const resolvedRole = userData?.role || finalRole;
      if (resolvedRole === 'doctor') {
        const { error: doctorError } = await supabase
          .from('doctors')
          .upsert({
            user_id: user.id,
            specialty: 'Not specified',
            years_experience: 0,
            hospital_name: 'Not specified',
            medical_license: 'Pending',
            hourly_rate: 0,
            bio: '',
            verification_status: 'pending'
          }, { onConflict: 'user_id', ignoreDuplicates: true });

        if (doctorError) throw doctorError;
        profileComplete = false;
      } else if (resolvedRole === 'patient') {
        const { error: patientError } = await supabase
          .from('patients')
          .upsert({ user_id: user.id }, { onConflict: 'user_id', ignoreDuplicates: true });

        if (patientError) throw patientError;
      }
    }

    res.json({
      success: true,
      userId: userData.id,
      email: userData.email,
      fullName: userData.full_name,
      role: userData.role,
      doctorProfile,
      profileComplete,
    });
  } catch (error) {
    console.error('❌ OAuth callback error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// PROFILE UPDATE ROUTES
// ============================================

// Upload Doctor License Document
// TODO: Uncomment after installing multer: npm install multer
// app.post('/api/doctors/:userId/upload-license', requireAuth, upload.single('licenseDocument'), async (req, res) => {
//   try {
//     const { userId } = req.params;
//     
//     // Verify user is a doctor
//     const { data: user, error: userError } = await supabase
//       .from('users')
//       .select('role')
//       .eq('id', userId)
//       .single();
//
//     if (userError || !user || user.role !== 'doctor') {
//       return res.status(403).json({ error: 'Only doctors can upload license documents' });
//     }
//
//     if (!req.file) {
//       return res.status(400).json({ error: 'No file uploaded' });
//     }
//
//     // Convert file to base64 for storage in Supabase
//     const base64 = req.file.buffer.toString('base64');
//     const fileData = `data:${req.file.mimetype};base64,${base64}`;
//
//     // Update doctor profile with license document
//     const { error: updateError } = await supabase
//       .from('doctors')
//       .update({
//         license_document: fileData,
//         license_document_name: req.file.originalname,
//         license_document_type: req.file.mimetype,
//         verification_status: 'pending' // Set to pending when document is uploaded
//       })
//       .eq('user_id', userId);
//
//     if (updateError) throw updateError;
//
//     res.json({
//       success: true,
//       message: 'License document uploaded successfully. Your verification is now pending review.'
//     });
//   } catch (error) {
//     console.error('❌ Upload license error:', error.message);
//     res.status(500).json({ error: 'Failed to upload license document' });
//   }
// });

// Update User Profile
app.patch('/api/users/:userId/profile', requireAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const {
      full_name,
      email,
      medical_license,
      phone,
      avatar,
      date_of_birth,
      gender,
      bio,
      location,
      preferred_language,
      specialty,
      years_experience,
      hospital_name,
      hourly_rate,
    } = req.body;

    // IDOR Protection: Verify the authenticated user is updating their own profile
    if (req.userId !== userId) {
      return res.status(403).json({ error: 'Forbidden: You can only update your own profile' });
    }

    // Verify user exists
    const { data: user, error: userError } = await supabase
      .from('users')
      .select('role, full_name')
      .eq('id', userId)
      .single();

    if (userError || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update users table
    const userUpdateData = {};
    if (full_name) userUpdateData.full_name = full_name;
    if (email) userUpdateData.email = email;
    if (phone) userUpdateData.phone = phone;
    if (avatar) userUpdateData.profile_image_url = avatar;

    if (Object.keys(userUpdateData).length > 0) {
      const { error: updateError } = await supabase
        .from('users')
        .update(userUpdateData)
        .eq('id', userId);

      if (updateError) throw updateError;
    }

    // Update role-specific table
    if (user.role === 'patient') {
      const patientUpdateData = {};
      if (date_of_birth) patientUpdateData.date_of_birth = date_of_birth;
      if (gender) patientUpdateData.gender = gender;
      if (bio) patientUpdateData.bio = bio;
      if (location) patientUpdateData.location = location;
      if (preferred_language) patientUpdateData.preferred_language = preferred_language;

      if (Object.keys(patientUpdateData).length > 0) {
        const { error: patientError } = await supabase
          .from('patients')
          .update(patientUpdateData)
          .eq('user_id', userId);

        if (patientError) throw patientError;
      }
    } else if (user.role === 'doctor') {
      const { data: existingDoctorProfile, error: existingDoctorError } = await supabase
        .from('doctors')
        .select('*')
        .eq('user_id', userId)
        .single();

      if (existingDoctorError || !existingDoctorProfile) {
        return res.status(404).json({ error: 'Doctor profile not found' });
      }

      const wasProfileComplete = isDoctorProfileComplete(existingDoctorProfile);
      const doctorUpdateData = {};
      if (medical_license !== undefined) {
        const normalizedLicense = String(medical_license).trim();
        if (!isAcceptableDoctorLicense(normalizedLicense)) {
          return res.status(400).json({ error: 'Use a valid medical license number in the accepted format' });
        }
        doctorUpdateData.medical_license = normalizedLicense;
      }
      if (specialty) doctorUpdateData.specialty = specialty;
      if (years_experience) doctorUpdateData.years_experience = years_experience;
      if (hospital_name) doctorUpdateData.hospital_name = hospital_name;
      if (hourly_rate !== undefined && hourly_rate !== null && hourly_rate !== '') {
        doctorUpdateData.hourly_rate = Number(hourly_rate);
      }
      if (bio) doctorUpdateData.bio = bio;
      if (location) doctorUpdateData.location = location;
      if (preferred_language) doctorUpdateData.preferred_language = preferred_language;

      if (Object.keys(doctorUpdateData).length > 0) {
        const { error: doctorError } = await supabase
          .from('doctors')
          .update(doctorUpdateData)
          .eq('user_id', userId);

        if (doctorError) throw doctorError;
      }

      const { data: completedDoctorProfile, error: completedDoctorError } = await supabase
        .from('doctors')
        .select('*')
        .eq('user_id', userId)
        .single();

      if (completedDoctorError) throw completedDoctorError;

      if (!wasProfileComplete && isDoctorProfileComplete(completedDoctorProfile)) {
        try {
          const { data: admins, error: adminsError } = await supabase
            .from('users')
            .select('id')
            .eq('role', 'admin');

          if (adminsError) throw adminsError;

          const adminNotifications = (admins || []).map(admin => ({
            user_id: admin.id,
            type: 'doctor_application_submitted',
            title: 'New doctor application',
            message: `${full_name || user.full_name || 'A doctor'} completed a doctor profile and is awaiting verification. Specialty: ${completedDoctorProfile.specialty}. Hospital: ${completedDoctorProfile.hospital_name}. License: ${completedDoctorProfile.medical_license}.`,
            data: {
              doctorId: completedDoctorProfile.id,
              userId,
              specialty: completedDoctorProfile.specialty,
              hospitalName: completedDoctorProfile.hospital_name,
              yearsExperience: completedDoctorProfile.years_experience,
              medicalLicense: completedDoctorProfile.medical_license,
            },
            is_read: false,
          }));

          if (adminNotifications.length > 0) {
            const { error: notificationError } = await supabase
              .from('notifications')
              .insert(adminNotifications);
            if (notificationError) throw notificationError;
          }
        } catch (notificationError) {
          console.error('Failed to notify admins of doctor application:', notificationError.message);
        }
      }
    }

    // Fetch updated user data and return the server-trusted completion state.
    const { data: updatedUser, error: fetchError } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (fetchError) throw fetchError;

    let updatedDoctorProfile = null;
    let profileComplete = true;
    if (user.role === 'doctor') {
      const { data: doctorProfile, error: doctorProfileError } = await supabase
        .from('doctors')
        .select('*')
        .eq('user_id', userId)
        .single();

      if (doctorProfileError) throw doctorProfileError;
      updatedDoctorProfile = doctorProfile;
      profileComplete = isDoctorProfileComplete(doctorProfile);
    }

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: updatedUser,
      doctorProfile: updatedDoctorProfile,
      profileComplete,
    });
  } catch (error) {
    console.error('❌ Update profile error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// DOCTORS ROUTES
// ============================================

// Get all doctors (with filtering) - Only approved doctors
app.get('/api/doctors', async (req, res) => {
  try {
    const { specialty, minRating, maxRate, includeAll } = req.query;

    // Security: includeAll parameter requires admin authorization
    if (includeAll) {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: Admin access required for includeAll' });
      }

      const token = authHeader.substring(7);
      const { data: { user }, error: authError } = await supabase.auth.getUser(token);
      
      if (authError || !user) {
        return res.status(401).json({ error: 'Invalid token' });
      }

      // Verify user is admin
      const { data: userData, error: userError } = await supabase
        .from('users')
        .select('role')
        .eq('id', user.id)
        .single();

      if (userError || !userData || userData.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Admin access required for includeAll' });
      }
    }

    let query = supabase
      .from('doctors')
      .select('id, user_id, specialty, bio, hospital_name, years_experience, hourly_rate, average_rating, total_consultations, verification_status, rejection_reason, verified_at, verified_by, created_at, updated_at');

    // Only show approved doctors unless explicitly requested (for admin)
    if (!includeAll) {
      query = query.eq('verification_status', 'approved');
    }

    // Apply filters
    if (specialty) {
      query = query.ilike('specialty', `%${specialty}%`);
    }

    if (minRating) {
      query = query.gte('average_rating', parseFloat(minRating));
    }

    if (maxRate) {
      query = query.lte('hourly_rate', parseFloat(maxRate));
    }

    const { data, error } = await query.order('average_rating', { ascending: false });

    if (error) throw error;

    const usersById = await getUsersByIds((data || []).map(doc => doc.user_id));

    // Format response - use snake_case to match frontend expectations
    const enriched = data.map(doc => ({
      id: doc.id,
      user_id: doc.user_id,
      name: usersById.get(doc.user_id)?.full_name,
      email: usersById.get(doc.user_id)?.email,
      profile_image_url: usersById.get(doc.user_id)?.profile_image_url,
      phone: usersById.get(doc.user_id)?.phone,
      specialty: doc.specialty,
      bio: doc.bio,
      hospital_name: doc.hospital_name,
      years_experience: doc.years_experience,
      hourly_rate: doc.hourly_rate,
      average_rating: doc.average_rating || 0,
      total_consultations: doc.total_consultations || 0,
      created_at: doc.created_at,
      updated_at: doc.updated_at,
    }));

    res.json(enriched);
  } catch (error) {
    console.error('❌ Get doctors error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Get doctors by verification status (for admin)
app.get('/api/doctors/status/:status', requireAdmin, async (req, res) => {
  try {
    const { status } = req.params;
    const validStatuses = ['pending', 'approved', 'rejected'];
    
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(', ')}` });
    }

    const { data, error } = await supabase
      .from('doctors')
      .select('*')
      .eq('verification_status', status)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const usersById = await getUsersByIds((data || []).map(doc => doc.user_id));

    res.json((data || []).map(doc => ({
      ...doc,
      users: usersById.get(doc.user_id) || null,
    })));
  } catch (error) {
    console.error('❌ Get doctors by status error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Get single doctor
app.get('/api/doctors/:id', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('doctors')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error) throw error;

    if (data.verification_status !== 'approved') {
      const requestingUser = await supabase
        .from('users')
        .select('role')
        .eq('id', req.userId)
        .single();

      if (requestingUser.error || !['admin', 'doctor'].includes(requestingUser.data?.role)) {
        return res.status(404).json({ error: 'Doctor not found' });
      }
    }

    const usersById = await getUsersByIds([data.user_id]);
    const { data: ratings, error: ratingsError } = await supabase
      .from('ratings')
      .select('*')
      .eq('doctor_id', req.params.id)
      .order('created_at', { ascending: false });

    if (ratingsError) throw ratingsError;

    // Format response to match frontend expectations
    res.json({
      id: data.id,
      user_id: data.user_id,
      name: usersById.get(data.user_id)?.full_name,
      email: usersById.get(data.user_id)?.email,
      profile_image_url: usersById.get(data.user_id)?.profile_image_url,
      phone: usersById.get(data.user_id)?.phone,
      specialty: data.specialty,
      bio: data.bio,
      hospital: data.hospital_name,
      hospital_name: data.hospital_name,
      years_experience: data.years_experience,
      hourly_rate: data.hourly_rate,
      average_rating: data.average_rating || 0,
      total_consultations: data.total_consultations || 0,
      medical_license: data.medical_license,
      verification_status: data.verification_status,
      rejection_reason: data.rejection_reason,
      verified_at: data.verified_at,
      verified_by: data.verified_by,
      created_at: data.created_at,
      updated_at: data.updated_at,
      reviewCount: ratings?.length || 0,
      reviews: ratings || []
    });
  } catch (error) {
    console.error('❌ Get doctor error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// APPOINTMENTS ROUTES
// ============================================

// Create appointment
app.post('/api/appointments', requireAuth, async (req, res) => {
  try {
    const { patientId, doctorId, appointmentDate, reason, consultationType } = req.body;

    if (!patientId || !doctorId || !appointmentDate) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // IDOR Protection: Verify the authenticated user is booking for themselves
    if (req.userId !== patientId) {
      return res.status(403).json({ error: 'Forbidden: You can only book appointments for yourself' });
    }

    // Security: Verify the doctor exists and is approved
    const { data: doctor, error: doctorError } = await supabase
      .from('doctors')
      .select('id, verification_status')
      .eq('id', doctorId)
      .single();

    if (doctorError || !doctor) {
      return res.status(404).json({ error: 'Doctor not found' });
    }

    if (doctor.verification_status !== 'approved') {
      return res.status(403).json({ error: 'Cannot book appointments with unapproved doctors' });
    }

    const { data, error } = await supabase
      .from('appointments')
      .insert({
        patient_id: patientId,
        doctor_id: doctorId,
        appointment_date: appointmentDate,
        reason_for_visit: reason || 'General consultation',
        consultation_type: consultationType || 'telehealth',
        status: 'pending',
      })
      .select();

    if (error) throw error;

    const { data: doctorOwner, error: doctorOwnerError } = await supabase
      .from('doctors')
      .select('user_id')
      .eq('id', doctorId)
      .single();

    if (doctorOwnerError || !doctorOwner) throw doctorOwnerError || new Error('Doctor owner not found');

    try {
      const { data: patientOwner } = await supabase
        .from('users')
        .select('full_name')
        .eq('id', patientId)
        .single();

      await insertNotification({
        userId: doctorOwner.user_id,
        type: 'appointment_requested',
        title: 'New appointment request',
        message: `${patientOwner?.full_name || 'A patient'} requested an appointment for ${new Date(data[0].appointment_date).toLocaleString()}.`,
        data: { appointmentId: data[0].id },
      });
    } catch (notifyErr) {
      console.error('❌ Failed to notify doctor of appointment request:', notifyErr.message);
    }

    res.status(201).json({
      success: true,
      appointment: data[0],
      message: 'Appointment created. Pending doctor confirmation.'
    });
  } catch (error) {
    console.error('❌ Create appointment error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Get appointments for user (patient or doctor)
app.get('/api/appointments/:userId/:role', requireAuth, async (req, res) => {
  try {
    const { userId, role } = req.params;

    if (!userId || !role) {
      return res.status(400).json({ error: 'userId and role required' });
    }

    // IDOR Protection: Verify the authenticated user is accessing their own appointments
    if (req.userId !== userId) {
      return res.status(403).json({ error: 'Forbidden: You can only access your own appointments' });
    }

    let query = supabase
      .from('appointments')
      .select('*')
      .order('appointment_date', { ascending: false });

    // Filter based on role
    if (role === 'patient') {
      const { data: patient, error: patientError } = await supabase
        .from('patients')
        .select('id')
        .eq('user_id', userId)
        .single();
      if (patientError || !patient) return res.json([]);
      query = query.eq('patient_id', patient.id);
    } else if (role === 'doctor') {
      const { data: doctor, error: doctorError } = await supabase
        .from('doctors')
        .select('id')
        .eq('user_id', userId)
        .single();
      if (doctorError || !doctor) return res.json([]);
      query = query.eq('doctor_id', doctor.id);
    } else {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const { data, error } = await query;

    if (error) throw error;

    const appointments = data || [];
    const doctorIds = appointments.map(appointment => appointment.doctor_id);
    const patientIds = appointments.map(appointment => appointment.patient_id);
    const [{ data: doctors, error: doctorsError }, { data: patients, error: patientsError }] = await Promise.all([
      supabase.from('doctors').select('id, user_id, specialty, hourly_rate').in('id', doctorIds),
      supabase.from('patients').select('id, user_id').in('id', patientIds),
    ]);

    if (doctorsError) throw doctorsError;
    if (patientsError) throw patientsError;

    const doctorsById = new Map((doctors || []).map(doctor => [doctor.id, doctor]));
    const patientsById = new Map((patients || []).map(patient => [patient.id, patient]));
    const usersById = await getUsersByIds([
      ...(doctors || []).map(doctor => doctor.user_id),
      ...(patients || []).map(patient => patient.user_id),
    ]);

    // Format response to match frontend expectations
    const formatted = appointments.map(apt => {
      const doctor = doctorsById.get(apt.doctor_id);
      const patient = patientsById.get(apt.patient_id);
      const doctorUser = usersById.get(doctor?.user_id);
      const patientUser = usersById.get(patient?.user_id);

      return ({
      id: apt.id,
      appointment_date: apt.appointment_date,
      reason_for_visit: apt.reason_for_visit,
      consultation_type: apt.consultation_type,
      status: apt.status,
      created_at: apt.created_at,
      updated_at: apt.updated_at,
      // Doctor info - flatten structure for frontend
      doctor_id: {
        id: doctor?.id,
        user_id: doctor?.user_id,
        specialty: doctor?.specialty,
        hourly_rate: doctor?.hourly_rate,
        users: {
          id: doctorUser?.id,
          full_name: doctorUser?.full_name,
          email: doctorUser?.email,
          profile_image_url: doctorUser?.profile_image_url
        }
      },
      // Patient info - flatten structure for frontend
      patient_id: {
        id: patient?.id,
        user_id: patient?.user_id,
        users: {
          id: patientUser?.id,
          full_name: patientUser?.full_name,
          email: patientUser?.email
        }
      }
      });
    });

    res.json(formatted);
  } catch (error) {
    console.error('❌ Get appointments error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Update appointment status and notify the patient in-app
app.patch('/api/appointments/:id', requireAuth, async (req, res) => {
  try {
    const { status: requestedStatus, reason, proposedDate, appointment_date } = req.body;
    const appointmentId = req.params.id;

    if (!requestedStatus) {
      return res.status(400).json({ error: 'Status is required' });
    }

    // Allowed status transitions in this handler: confirmed, cancelled, rescheduled, completed
    const status = requestedStatus === 'declined' ? 'cancelled' : requestedStatus;
    const isLegacyReschedule = requestedStatus === 'confirmed' && appointment_date;
    const effectiveStatus = isLegacyReschedule ? 'rescheduled' : status;
    const allowed = ['confirmed', 'cancelled', 'rescheduled', 'completed'];
    if (!allowed.includes(effectiveStatus)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${allowed.join(', ')}` });
    }

    // Fetch the appointment and resolve related records explicitly.
    const { data: appointment, error: aptErr } = await supabase
      .from('appointments')
      .select('*')
      .eq('id', appointmentId)
      .single();

    if (aptErr || !appointment) {
      return res.status(404).json({ error: 'Appointment not found' });
    }

    const [{ data: doctor, error: doctorError }, { data: patient, error: patientError }] = await Promise.all([
      supabase.from('doctors').select('user_id').eq('id', appointment.doctor_id).single(),
      supabase.from('patients').select('user_id').eq('id', appointment.patient_id).single(),
    ]);

    if (doctorError || !doctor || patientError || !patient) {
      return res.status(404).json({ error: 'Appointment participants not found' });
    }

    const doctorUserId = doctor.user_id;
    const patientUserId = patient.user_id;

    // Authorization: only the doctor can confirm/reschedule/decline (cancel) from doctor side
    if (['confirmed', 'rescheduled', 'cancelled'].includes(effectiveStatus)) {
      if (req.userId !== doctorUserId) {
        return res.status(403).json({ error: 'Forbidden: Only the assigned doctor can perform this action' });
      }
    }

    // Prevent duplicate actions
    if (appointment.status === 'confirmed' && effectiveStatus === 'confirmed') {
      return res.status(400).json({ error: 'Appointment already confirmed' });
    }

    const updateData = { status: effectiveStatus, updated_at: new Date().toISOString() };

    // Handle decline/cancel reason
    if (effectiveStatus === 'cancelled') {
      if (!reason || reason.trim().length === 0) {
        return res.status(400).json({ error: 'Reason is required for cancelling/declining an appointment' });
      }
      updateData.decline_reason = reason;
    }

    // Handle reschedule proposal from doctor
    if (effectiveStatus === 'rescheduled') {
      const requestedDate = proposedDate || appointment_date;
      if (!requestedDate) {
        return res.status(400).json({ error: 'proposedDate is required when rescheduling' });
      }
      // Store proposed date and set status to rescheduled
      updateData.proposed_date = requestedDate;
      updateData.status = 'rescheduled';
    }

    // Update appointment
    const { data, error } = await supabase
      .from('appointments')
      .update(updateData)
      .eq('id', appointmentId)
      .eq('status', appointment.status)
      .select()
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(409).json({ error: 'Appointment was already updated' });
      }
      throw error;
    }

    // Create in-app notification for patient
    try {
      const titleMap = {
        confirmed: 'Appointment confirmed',
        cancelled: 'Appointment declined',
        rescheduled: 'Appointment rescheduled',
      };

      const messageMap = {
        confirmed: `Your appointment has been approved by the doctor for ${new Date(data.appointment_date).toLocaleString()}.`,
        cancelled: `Your appointment on ${new Date(appointment.appointment_date).toLocaleString()} was declined by the doctor. Reason: ${reason}`,
        rescheduled: `The doctor proposed a new appointment time: ${new Date(data.proposed_date).toLocaleString()}. Please review and confirm.`,
      };

      await insertNotification({
        userId: patientUserId,
        type: `appointment_${effectiveStatus}`,
        title: titleMap[effectiveStatus] || 'Appointment update',
        message: messageMap[effectiveStatus] || 'Your appointment was updated.',
        data: { appointmentId },
      });
    } catch (notifErr) {
      console.error('❌ Failed to create in-app notification:', notifErr.message);
    }

    res.json({
      success: true,
      appointment: data,
      message: `Appointment ${updateData.status}. Patient notified in CareConnect.`,
    });
  } catch (error) {
    console.error('❌ Update appointment error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

// Get admin dashboard stats
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    // Get counts for each verification status
    const { count: pendingDoctors, error: pendingError } = await supabase
      .from('doctors')
      .select('id', { count: 'exact', head: true })
      .eq('verification_status', 'pending');

    const { count: approvedDoctors, error: approvedError } = await supabase
      .from('doctors')
      .select('id', { count: 'exact', head: true })
      .eq('verification_status', 'approved');

    const { count: rejectedDoctors, error: rejectedError } = await supabase
      .from('doctors')
      .select('id', { count: 'exact', head: true })
      .eq('verification_status', 'rejected');

    // Count patients from users table with role='patient'
    const { count: patients, error: patientsError } = await supabase
      .from('users')
      .select('id', { count: 'exact', head: true })
      .eq('role', 'patient');

    const { count: appointments, error: appointmentsError } = await supabase
      .from('appointments')
      .select('id', { count: 'exact', head: true });

    if (pendingError || approvedError || rejectedError || patientsError || appointmentsError) {
      throw new Error('Failed to fetch stats');
    }

    res.json({
      pendingDoctors: pendingDoctors || 0,
      approvedDoctors: approvedDoctors || 0,
      rejectedDoctors: rejectedDoctors || 0,
      totalPatients: patients || 0,
      totalAppointments: appointments || 0,
    });
  } catch (error) {
    console.error('❌ Get admin stats error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Approve doctor
app.patch('/api/admin/doctors/:doctorId/approve', requireAdmin, async (req, res) => {
  try {
    const { doctorId } = req.params;
    const adminId = req.adminId;

    // Update doctor verification status
    const { data, error } = await supabase
      .from('doctors')
      .update({
        verification_status: 'approved',
        verified_at: new Date().toISOString(),
        verified_by: adminId,
        rejection_reason: null
      })
      .eq('id', doctorId)
      .eq('verification_status', 'pending')
      .select()
      .single();

    if (error) {
      if (error.code === 'PGRST116') {
        return res.status(409).json({ error: 'Doctor application was already processed' });
      }
      throw error;
    }

    // Create in-app notifications for all patients informing new doctor availability
    try {
      const { data: patients } = await supabase
        .from('users')
        .select('id')
        .eq('role', 'patient');

      if (patients && patients.length > 0) {
        const notifications = patients.map(p => ({
          user_id: p.id,
          type: 'doctor_approved_discovery',
          title: 'New doctor available',
          message: 'A newly verified doctor has joined CareConnect. Refresh to see newly added doctors.',
          data: { doctorId },
          is_read: false,
        }));

        await supabase.from('notifications').insert(notifications);
      }
    } catch (notifyErr) {
      console.error('❌ Failed to create patient notifications:', notifyErr.message);
      // Don't fail the main request if notification insert fails
    }

    res.json({
      success: true,
      message: 'Doctor approved successfully',
      doctor: data,
    });
  } catch (error) {
    console.error('❌ Approve doctor error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Reject doctor
app.patch('/api/admin/doctors/:doctorId/reject', requireAdmin, async (req, res) => {
  try {
    const { doctorId } = req.params;
    const { rejectionReason } = req.body;
    const adminId = req.adminId;

    // Update doctor verification status
    const { data, error } = await supabase
      .from('doctors')
      .update({
        verification_status: 'rejected',
        rejection_reason: rejectionReason || 'Application rejected',
        verified_at: null,
        verified_by: adminId
      })
      .eq('id', doctorId)
      .select()
      .single();

    if (error) throw error;

    // Notify the doctor about rejection (if possible)
    try {
      // Get doctor user_id
      const { data: doc } = await supabase
        .from('doctors')
        .select('user_id')
        .eq('id', doctorId)
        .single();

      if (doc && doc.user_id) {
        await insertNotification({
          userId: doc.user_id,
          type: 'doctor_verification_rejected',
          title: 'Doctor verification declined',
          message: `Your doctor verification request was declined. Reason: ${rejectionReason || 'Not specified'}`,
          data: { doctorId },
        });
      }
    } catch (notifyErr) {
      console.error('❌ Failed to notify doctor of rejection:', notifyErr.message);
    }

    res.json({
      success: true,
      message: 'Doctor rejected successfully',
      doctor: data,
    });
  } catch (error) {
    console.error('❌ Reject doctor error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// ============================================
// NOTIFICATIONS ROUTES
// ============================================

// Get notifications for authenticated user
app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const userId = req.userId;
    const { data, error } = await supabase
      .from('notifications')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) throw error;

    res.json(data);
  } catch (error) {
    console.error('❌ Get notifications error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// Mark notification as read
app.patch('/api/notifications/:id/read', requireAuth, async (req, res) => {
  try {
    const notifId = req.params.id;
    const userId = req.userId;

    // Ensure notification belongs to user
    const { data: notif, error: findErr } = await supabase
      .from('notifications')
      .select('*')
      .eq('id', notifId)
      .single();

    if (findErr || !notif) return res.status(404).json({ error: 'Notification not found' });
    if (notif.user_id !== userId) return res.status(403).json({ error: 'Forbidden' });

    const { data, error } = await supabase
      .from('notifications')
      .update({ is_read: true })
      .eq('id', notifId)
      .select()
      .single();

    if (error) throw error;

    res.json({ success: true, notification: data });
  } catch (error) {
    console.error('❌ Mark notification read error:', error.message);
    res.status(500).json({ error: error.message });
  }
});


// ============================================
// RATINGS ROUTES
// ============================================

// Create rating
app.post('/api/ratings', requireAuth, async (req, res) => {
  try {
    const { patientId, doctorId, appointmentId, rating, reviewText } = req.body;

    if (!patientId || !doctorId || !rating) {
      return res.status(400).json({ error: 'patientId, doctorId, and rating required' });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ error: 'Rating must be between 1 and 5' });
    }

    const { data, error } = await supabase
      .from('ratings')
      .insert({
        patient_id: patientId,
        doctor_id: doctorId,
        appointment_id: appointmentId || null,
        rating,
        review_text: reviewText || '',
      })
      .select();

    if (error) throw error;

    // Update doctor's average rating
    const { data: ratings, error: ratingsError } = await supabase
      .from('ratings')
      .select('rating')
      .eq('doctor_id', doctorId);

    if (!ratingsError && ratings && ratings.length > 0) {
      const avgRating = ratings.reduce((sum, r) => sum + r.rating, 0) / ratings.length;
      await supabase
        .from('doctors')
        .update({
          average_rating: parseFloat(avgRating.toFixed(2)),
          total_consultations: ratings.length,
        })
        .eq('id', doctorId);
    }

    res.status(201).json({
      success: true,
      rating: data[0],
      message: 'Rating submitted. Thank you!'
    });
  } catch (error) {
    console.error('❌ Create rating error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Get ratings for a doctor
app.get('/api/ratings/:doctorId', requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('ratings')
      .select('*')
      .eq('doctor_id', req.params.doctorId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const usersById = await getUsersByIds((data || []).map(rating => rating.patient_id));
    res.json((data || []).map(rating => ({
      ...rating,
      patient: usersById.get(rating.patient_id) || null,
    })));
  } catch (error) {
    console.error('❌ Get ratings error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// ERROR HANDLING
// ============================================
app.use((err, req, res, next) => {
  console.error('🔴 Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log('');
  console.log('╔════════════════════════════════════════╗');
  console.log('║     🏥 CareConnect Backend Server     ║');
  console.log('╚════════════════════════════════════════╝');
  console.log('');
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📡 API endpoints ready`);
  console.log(`🔗 Supabase connected`);
  console.log('');
  console.log('Available endpoints:');
  console.log('  POST   /api/auth/signup');
  console.log('  POST   /api/auth/login');
  console.log('  PATCH  /api/users/:userId/profile');
  console.log('  GET    /api/doctors');
  console.log('  GET    /api/doctors/:id');
  console.log('  GET    /api/doctors/status/:status');
  console.log('  POST   /api/appointments');
  console.log('  GET    /api/appointments/:userId/:role');
  console.log('  PATCH  /api/appointments/:id');
  console.log('  POST   /api/ratings');
  console.log('  GET    /api/ratings/:doctorId');
  console.log('  GET    /api/admin/stats');
  console.log('  PATCH  /api/admin/doctors/:doctorId/approve');
  console.log('  PATCH  /api/admin/doctors/:doctorId/reject');
  console.log('');
});

export default app;