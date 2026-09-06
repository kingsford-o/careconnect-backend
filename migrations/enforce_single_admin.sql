-- CareConnect: enforce a single admin account
-- Run the duplicate check first. This migration never deletes or changes users.

DO $$
DECLARE
  admin_count INTEGER;
BEGIN
  SELECT COUNT(*) INTO admin_count
  FROM public.users
  WHERE role = 'admin';

  IF admin_count > 1 THEN
    RAISE EXCEPTION 'Cannot enforce single admin: public.users currently contains % admin accounts. Resolve duplicates first.', admin_count;
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS one_admin_only
  ON public.users (role)
  WHERE role = 'admin';

COMMENT ON INDEX one_admin_only IS 'Ensures CareConnect has at most one admin account';
