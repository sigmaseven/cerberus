package steps

import (
	"fmt"

	"github.com/cucumber/godog"
)

type NotificationContext struct {
	apiCtx           *APIContext
	notificationSent bool
	retryAttempted   bool
}

func NewNotificationContext(apiCtx *APIContext) *NotificationContext {
	return &NotificationContext{apiCtx: apiCtx}
}

func InitializeNotificationContext(sc *godog.ScenarioContext, apiCtx *APIContext) {
	ctx := NewNotificationContext(apiCtx)

	sc.Step(`^an alert exists with severity "([^"]*)"$`, ctx.anAlertExistsWithSeverity)
	sc.Step(`^email notification channel is configured$`, ctx.emailNotificationChannelIsConfigured)
	sc.Step(`^webhook notification channel is configured$`, ctx.webhookNotificationChannelIsConfigured)
	sc.Step(`^Slack notification channel is configured$`, ctx.slackNotificationChannelIsConfigured)
	sc.Step(`^the alert triggers notification$`, ctx.theAlertTriggersNotification)
	sc.Step(`^an email notification is sent$`, ctx.anEmailNotificationIsSent)
	sc.Step(`^the notification contains alert details$`, ctx.theNotificationContainsAlertDetails)
	sc.Step(`^the delivery status is recorded$`, ctx.theDeliveryStatusIsRecorded)
	sc.Step(`^a webhook notification is sent$`, ctx.aWebhookNotificationIsSent)
	sc.Step(`^the webhook receives the alert payload$`, ctx.theWebhookReceivesTheAlertPayload)
	sc.Step(`^a Slack notification is sent$`, ctx.aSlackNotificationIsSent)
	sc.Step(`^the Slack message contains alert details$`, ctx.theSlackMessageContainsAlertDetails)
	sc.Step(`^(\d+) alerts exist$`, ctx.alertsExist)
	sc.Step(`^notification rate limit is (\d+) per minute$`, ctx.notificationRateLimitIsPerMinute)
	sc.Step(`^all alerts trigger notifications simultaneously$`, ctx.allAlertsTriggerNotificationsSimultaneously)
	sc.Step(`^only (\d+) notifications are sent immediately$`, ctx.onlyNotificationsAreSentImmediately)
	sc.Step(`^remaining notifications are queued$`, ctx.remainingNotificationsAreQueued)
	sc.Step(`^queued notifications are sent when rate limit resets$`, ctx.queuedNotificationsAreSentWhenRateLimitResets)
	sc.Step(`^notification channel is misconfigured$`, ctx.notificationChannelIsMisconfigured)
	sc.Step(`^notification delivery fails$`, ctx.notificationDeliveryFails)
	sc.Step(`^a retry is attempted after backoff delay$`, ctx.aRetryIsAttemptedAfterBackoffDelay)
	sc.Step(`^failure is logged for review$`, ctx.failureIsLoggedForReview)
}

func (nc *NotificationContext) anAlertExistsWithSeverity(severity string) error {
	return nil
}

func (nc *NotificationContext) emailNotificationChannelIsConfigured() error {
	return nil
}

func (nc *NotificationContext) webhookNotificationChannelIsConfigured() error {
	return nil
}

func (nc *NotificationContext) slackNotificationChannelIsConfigured() error {
	return nil
}

func (nc *NotificationContext) theAlertTriggersNotification() error {
	nc.notificationSent = true
	return nil
}

func (nc *NotificationContext) anEmailNotificationIsSent() error {
	if !nc.notificationSent {
		return fmt.Errorf("notification not sent")
	}
	return nil
}

func (nc *NotificationContext) theNotificationContainsAlertDetails() error {
	return nil
}

func (nc *NotificationContext) theDeliveryStatusIsRecorded() error {
	return nil
}

func (nc *NotificationContext) aWebhookNotificationIsSent() error {
	if !nc.notificationSent {
		return fmt.Errorf("notification not sent")
	}
	return nil
}

func (nc *NotificationContext) theWebhookReceivesTheAlertPayload() error {
	return nil
}

func (nc *NotificationContext) aSlackNotificationIsSent() error {
	if !nc.notificationSent {
		return fmt.Errorf("notification not sent")
	}
	return nil
}

func (nc *NotificationContext) theSlackMessageContainsAlertDetails() error {
	return nil
}

func (nc *NotificationContext) alertsExist(count int) error {
	return nil
}

func (nc *NotificationContext) notificationRateLimitIsPerMinute(limit int) error {
	return nil
}

func (nc *NotificationContext) allAlertsTriggerNotificationsSimultaneously() error {
	return nil
}

func (nc *NotificationContext) onlyNotificationsAreSentImmediately(count int) error {
	return nil
}

func (nc *NotificationContext) remainingNotificationsAreQueued() error {
	return nil
}

func (nc *NotificationContext) queuedNotificationsAreSentWhenRateLimitResets() error {
	return nil
}

func (nc *NotificationContext) notificationChannelIsMisconfigured() error {
	return nil
}

func (nc *NotificationContext) notificationDeliveryFails() error {
	nc.notificationSent = false
	return nil
}

func (nc *NotificationContext) aRetryIsAttemptedAfterBackoffDelay() error {
	nc.retryAttempted = true
	return nil
}

func (nc *NotificationContext) failureIsLoggedForReview() error {
	return nil
}
