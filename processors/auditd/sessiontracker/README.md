# Session Tracking Using Audito Maldito

## Auditor Interface

The `Auditor` interface can be implemented by adding `AuditdEvent()` method.
The `AuditdEvent()` requires that the input event is validated,
against the list of available event sessions.

```go
type Auditor interface {
	AuditdEvent(event *aucoalesce.Event) error
}
```

## Session Tracker

Session Tracker, `sessionTracker` is an implementation of the Auditor Interface.
You may create a new seesion tracker object as

```go
import "sessiontracker"

var tracker = sessiontracker.NewSessionTracker(o.EventW, logger)
```

It takes an `auditevent.EventWriter` and a `zap.SugaredLogger` object as parameters.

It contains active auditd sessions, a map of PIDs and remote user logins, and obviously an `auditevent.EventWriter` and a `zap.SugaredLogger`.

It has these methods
1. `RemoteLogin`
    It validates and sets a remote login input

    ### Usage

    ```go
    import "github.com/metal-toolbox/audito-maldito/processors/auditd/sessiontracker"

    func foo() {
        tracker := sessiontracker.NewSessionTracker(o.EventW, logger)
        err := tracker.RemoteLogin(common.RemoteUserLogin{
            Source:     nil,
            PID:        999,
            CredUserID: "foo",
        })
        if err != nil {
            return fmt.Errorf("failed to handle remote user login - %w", err)
        }
    }
    ```

2. `AuditdEvent`
    It's the primary method of this type, i.e., `sessionTracker`. It triggers the audit of the input audit event. A session is bound to it, if it matches a session in the session cache. If a session is bound then it calls `auditEventWithSession`, else it calls `auditEventWithoutSession`

    ### Usage

    ```go
    import "github.com/metal-toolbox/audito-maldito/processors/auditd/sessiontracker"
    
    func foo() error {
        st := sessiontracker.NewSessionTracker(o.EventW, logger)
        ae := &aucoalesce.Event{
            Session:   sessionID
        }
        err := st.AuditdEvent(ae)
        return err
    }
    ```

3. `DeleteUsersWithoutLoginsBefore`
    This method, as the name says, deletes the audit session before a given timestamp, if the user doesn't have a remote login.

    ### Usage

    ```go
    import "github.com/metal-toolbox/audito-maldito/processors/auditd/sessiontracker"
    
    func foo() error {
        st := sessiontracker.NewSessionTracker(o.EventW, logger)
        st.DeleteUsersWithoutLoginsBefore(time.Now())
    }
    ```

4. `DeleteRemoteUserLoginsBefore`
    It iterates over remote user logins and checks if a login was before the timestamp, then it deletes that remote user login.

    ### Usage

    ```go
    import "github.com/metal-toolbox/audito-maldito/processors/auditd/sessiontracker"
    
    func foo() error {
        st := sessiontracker.NewSessionTracker(o.EventW, logger)

        var staleDataCleanupInterval = 1 * time.Minute
        aMinuteAgo := time.Now().Add(-staleDataCleanupInterval)

		st.DeleteRemoteUserLoginsBefore(aMinuteAgo)
    }
    ```
    
## Error Definitions

### Error Types

1. SessionTrackerError 

    `SesstionTrackerError` tracks three different kinds of failures.
    1. Remote Login Failure
    2. Parse PID Failure
    3. Audit Write Failure

    Here is the struct for it

    ```go
    // SessionTrackerError is used to return errors pertaining to session audits
    type SessionTrackerError struct {
        remoteLoginFail bool   // set when remote login cannot be validated
        parsePIDFail    bool   // set when PID of the session cannot be parsed
        auditWriteFail  bool   // set when the audit event fails to write to event writer
        message         string // the error message
        inner           error  // the error object
    }
    ```

    ### Usage

    You may retun a session tracker error, `SessionTrackerError`, as below
    
    ```go
    return &SessionTrackerError{
        auditWriteFail: true,
        message: fmt.Sprintf(
            "failed to write cached events for user '%s' - %s",
            u.login.CredUserID, 
            err,
        ),
        inner: err,
    }
    ```

