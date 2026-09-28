ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_generation bigint NOT NULL DEFAULT 1;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_generation bigint NOT NULL DEFAULT 1;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT 'PENDING';
UPDATE notifications SET state = CASE WHEN sent IS NOT NULL THEN 'ACCEPTED' WHEN attempts >= 10 THEN 'FAILED' ELSE 'PENDING' END;
ALTER TABLE notifications DROP CONSTRAINT IF EXISTS notifications_state_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_state_check CHECK (state IN ('PENDING','FAILED','CANCELLED','ACCEPTED'));
CREATE INDEX IF NOT EXISTS notifications_state_available ON notifications(state, available) WHERE state IN ('PENDING','FAILED');
