package db

import (
	"context"
	"testing"
	"time"
)

// TestAccountSecurityResetRollsBack ensures cleanup failures cannot partially change credentials.
func TestAccountSecurityResetRollsBack(t *testing.T) {
	for _, twoFactor := range []bool{false, true} {
		t.Run(map[bool]string{false: "password", true: "two-factor"}[twoFactor], func(t *testing.T) {
			d := openTest(t)
			ctx := context.Background()
			a, err := d.CreateAccount(ctx, Account{Username: "member", Role: "member", PasswordHash: "old", TOTPEnabled: true, TOTPSecret: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			if err = d.ReplaceBackupCodes(ctx, a.ID, []string{"code"}); err != nil {
				t.Fatal(err)
			}
			if err = d.CreateSession(ctx, Session{ID: "session", AccountID: a.ID, CreatedAt: time.Now(), LastSeenAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
			if _, err = d.SQL.Exec(`CREATE TRIGGER fail_cleanup BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT, 'cleanup failed'); END`); err != nil {
				t.Fatal(err)
			}
			if twoFactor {
				err = d.ResetAccountTwoFactor(ctx, a.ID)
			} else {
				err = d.SetAccountPassword(ctx, a.ID, "new")
			}
			if err == nil {
				t.Fatal("ignored cleanup failure")
			}
			got, _ := d.GetAccount(ctx, a.ID)
			if got.PasswordHash != "old" || !got.TOTPEnabled || got.TOTPSecret != "secret" || d.RemainingBackupCodes(ctx, a.ID) != 1 {
				t.Fatal("credentials partially changed")
			}
			if _, err := d.GetSession(ctx, "session"); err != nil {
				t.Fatal("session lost on rollback")
			}
		})
	}
}
