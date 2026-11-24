package plainauth

import "context"

// backgroundTaskKey marks the context of a task already running through
// Options.BackgroundTasks, so work it awaits runs inline instead of being
// handed off again.
type backgroundTaskKey struct{ a *Auth }

// taskContext is the context of handed-off work. It keeps the request's
// values but not its cancellation or deadline, and hides the values that
// belong to the finished request: the endpoint's HookContext and the request
// copy. Database hooks then see a task's writes as a direct Go call.
type taskContext struct{ context.Context }

func (c taskContext) Value(key any) any {
	switch key.(type) {
	case hookContextKey, requestCopyKey:
		return nil
	}
	return c.Context.Value(key)
}

func (a *Auth) detach(ctx context.Context) context.Context {
	return context.WithValue(taskContext{context.WithoutCancel(ctx)}, backgroundTaskKey{a}, true)
}

// handOff gives task to Options.BackgroundTasks with a detached context. It
// reports false without a runner, and inside a task that is already in the
// background, which runs the work itself.
func (a *Auth) handOff(ctx context.Context, failure string, task func(context.Context) error) bool {
	if a.opts.BackgroundTasks == nil || ctx.Value(backgroundTaskKey{a}) != nil {
		return false
	}
	a.giveToRunner(ctx, failure, task)
	return true
}

func (a *Auth) giveToRunner(ctx context.Context, failure string, task func(context.Context) error) {
	detached := a.detach(ctx)
	defer func() {
		if recover() != nil {
			// The runner may already have started the task, so it is not run again.
			a.Logger().ErrorContext(ctx, "Could not start background task")
		}
	}()
	a.opts.BackgroundTasks(func() { a.runTask(detached, failure, task) })
}

// runTask runs handed-off work and logs failure, a fixed message without the
// error's text, when it fails or panics.
func (a *Auth) runTask(ctx context.Context, failure string, task func(context.Context) error) {
	defer func() {
		if recover() != nil {
			a.Logger().ErrorContext(ctx, failure)
		}
	}()
	if err := task(ctx); err != nil {
		a.Logger().ErrorContext(ctx, failure)
	}
}

// runInBackgroundOrAwait hands task off, or runs it before returning without
// a runner. Its errors are logged and never returned. Inline, a panic
// propagates as it would without this helper.
func (a *Auth) runInBackgroundOrAwait(ctx context.Context, failure string, task func(context.Context) error) {
	if a.handOff(ctx, failure, task) {
		return
	}
	if err := task(ctx); err != nil {
		a.Logger().ErrorContext(ctx, failure)
	}
}

// sendMailLink delivers a prepared link through runInBackgroundOrAwait. The
// request copy follows the task's context, which outlives the request.
func (a *Auth) sendMailLink(ctx context.Context, failure string, link MailLink, send MailSender) {
	a.runInBackgroundOrAwait(ctx, failure, func(ctx context.Context) error {
		if link.Request != nil {
			link.Request = link.Request.WithContext(ctx)
		}
		return send(ctx, link)
	})
}

// deliver runs a send. For a request to the handler it behaves like
// runInBackgroundOrAwait, so a delivery failure is logged and never changes
// the response, as in the reference. A direct Go call sends before returning
// and gets the sender's error.
func (a *Auth) deliver(ctx context.Context, failure string, task func(context.Context) error) error {
	if ctx.Value(requestCopyKey{a}) == nil {
		return task(ctx)
	}
	a.runInBackgroundOrAwait(ctx, failure, task)
	return nil
}

// deliverMail delivers a prepared link through deliver.
func (a *Auth) deliverMail(ctx context.Context, failure string, link MailLink, send MailSender) error {
	return a.deliver(ctx, failure, func(ctx context.Context) error {
		if link.Request != nil {
			link.Request = link.Request.WithContext(ctx)
		}
		return send(ctx, link)
	})
}

// deliverEmailProof builds a verification link, whose errors are returned,
// and delivers it through deliverMail.
func (a *Auth) deliverEmailProof(ctx context.Context, failure string, u User, newEmail, requestType, callback string, send MailSender) error {
	link, err := a.emailProofLink(ctx, u, newEmail, requestType, callback)
	if err != nil {
		return err
	}
	return a.deliverMail(ctx, failure, link, send)
}

// RunInBackground runs task after the current work: through
// Options.BackgroundTasks, also from inside another task, or on a new
// goroutine without a runner. The task's context keeps ctx's values but not
// its cancellation or deadline. A panic is logged.
func (a *Auth) RunInBackground(ctx context.Context, task func(context.Context)) {
	run := func(ctx context.Context) error {
		task(ctx)
		return nil
	}
	if a.opts.BackgroundTasks != nil {
		a.giveToRunner(ctx, "Background task failed", run)
		return
	}
	go a.runTask(a.detach(ctx), "Background task failed", run)
}

// RunInBackgroundOrAwait runs task through Options.BackgroundTasks, or before
// it returns without one. An error is logged, not returned; a handed-off
// task's panic is logged too.
func (a *Auth) RunInBackgroundOrAwait(ctx context.Context, task func(context.Context) error) {
	a.runInBackgroundOrAwait(ctx, "Background task failed", task)
}
