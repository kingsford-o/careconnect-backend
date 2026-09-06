-- ============================================
-- CareConnect Doctor Verification Migration
-- ============================================
-- This migration adds doctor verification workflow
-- Run this in your Supabase SQL editor

-- Add verification_status column to doctors table
ALTER TABLE doctors 
ADD COLUMN IF NOT EXISTS verification_status TEXT DEFAULT 'pending' 
CHECK (verification_status IN ('pending', 'approved', 'rejected'));

-- Add optional fields for verification metadata
ALTER TABLE doctors 
ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

ALTER TABLE doctors 
ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE doctors 
ADD COLUMN IF NOT EXISTS verified_by UUID REFERENCES users(id);

-- Create index for faster filtering of approved doctors
CREATE INDEX IF NOT EXISTS idx_doctors_verification_status 
ON doctors(verification_status);

-- Add comment for documentation
COMMENT ON COLUMN doctors.verification_status IS 'Doctor verification status: pending, approved, or rejected';
COMMENT ON COLUMN doctors.rejection_reason IS 'Reason for rejection if verification_status is rejected';
COMMENT ON COLUMN doctors.verified_at IS 'Timestamp when doctor was approved';
COMMENT ON COLUMN doctors.verified_by IS 'Admin user ID who approved this doctor';

-- Update existing doctors to have 'pending' status if null
UPDATE doctors 
SET verification_status = 'pending' 
WHERE verification_status IS NULL;

-- ============================================
-- Note: For production, you may want to create
-- a separate admin user manually through Supabase
-- ============================================
