package services

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/husa/backend/internal/models"
)

// NotificationService handles user notifications.
type NotificationService struct {
	db *sql.DB
}

// NewNotificationService creates a new NotificationService.
func NewNotificationService(db *sql.DB) *NotificationService {
	return &NotificationService{db: db}
}

// Create inserts a new notification for a user.
func (s *NotificationService) Create(userID, notifType, referenceID string) error {
	var refID interface{}
	if referenceID != "" {
		refID = referenceID
	}
	_, err := s.db.Exec(
		`INSERT INTO notifications (user_id, type, reference_id) VALUES ($1, $2, $3)`,
		userID, notifType, refID,
	)
	if err != nil {
		return fmt.Errorf("creating notification: %w", err)
	}
	return nil
}

// List returns all notifications for a user, newest first.
func (s *NotificationService) List(userID string, page, limit int) ([]models.Notification, error) {
	offset := (page - 1) * limit
	rows, err := s.db.Query(`
		SELECT id, user_id, type, reference_id, is_read, created_at
		FROM notifications
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`, userID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("listing notifications: %w", err)
	}
	defer rows.Close()

	var notifs []models.Notification
	for rows.Next() {
		var n models.Notification
		if err := rows.Scan(&n.ID, &n.UserID, &n.Type, &n.ReferenceID, &n.IsRead, &n.CreatedAt); err != nil {
			return nil, err
		}
		notifs = append(notifs, n)
	}
	return notifs, rows.Err()
}

// MarkRead marks a single notification as read. Only the owner may mark it.
func (s *NotificationService) MarkRead(notifID, userID string) error {
	result, err := s.db.Exec(
		`UPDATE notifications SET is_read = TRUE WHERE id = $1 AND user_id = $2`,
		notifID, userID,
	)
	if err != nil {
		return fmt.Errorf("marking notification read: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return errors.New("notification not found")
	}
	return nil
}

// MarkAllRead marks all unread notifications for a user as read.
func (s *NotificationService) MarkAllRead(userID string) error {
	_, err := s.db.Exec(
		`UPDATE notifications SET is_read = TRUE WHERE user_id = $1 AND is_read = FALSE`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("marking all notifications read: %w", err)
	}
	return nil
}
