-- Migration 003 introduced explicit notification states, but schema 2 used a
-- non-null sent timestamp for cancellations too. Repair only those historical
-- rows; the checksum of the already-applied migration remains unchanged.
UPDATE notifications
SET state='CANCELLED'
WHERE state='ACCEPTED'
  AND sent IS NOT NULL
  AND last_error LIKE 'Cancelled:%';
