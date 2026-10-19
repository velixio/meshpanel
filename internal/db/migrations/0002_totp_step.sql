-- Last TOTP time step accepted per account, so a code works only once.
ALTER TABLE accounts ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
