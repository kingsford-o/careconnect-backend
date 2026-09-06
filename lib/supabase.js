// backend/lib/supabase.js
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';

// Get the directory of this file
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from backend root (parent of lib)
const envPath = path.resolve(__dirname, '..', '.env');
dotenv.config({ path: envPath });

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

console.log('📂 Loading .env from:', envPath);
console.log('🔍 SUPABASE_URL:', supabaseUrl ? '✅ loaded' : '❌ missing');
console.log('🔍 SUPABASE_SERVICE_ROLE_KEY:', supabaseServiceRoleKey ? '✅ loaded' : '❌ missing');

if (!supabaseUrl) {
  throw new Error(`SUPABASE_URL not found. Checked: ${envPath}`);
}

if (!supabaseServiceRoleKey) {
  throw new Error(`SUPABASE_SERVICE_ROLE_KEY not found. Checked: ${envPath}`);
}

export const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);