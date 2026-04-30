package services

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/husa/backend/internal/models"
)

// MessageService handles direct messaging between users.
type MessageService struct {
	db *sql.DB
}

// NewMessageService creates a new MessageService.
func NewMessageService(db *sql.DB) *MessageService {
	return &MessageService{db: db}
}

// Send stores a new message from senderID to the receiver specified in req.
func (s *MessageService) Send(senderID string, req models.SendMessageRequest) (*models.Message, error) {
	if req.ReceiverID == "" || req.Content == "" {
		return nil, errors.New("receiver_id and content are required")
	}
	if senderID == req.ReceiverID {
		return nil, errors.New("cannot send a message to yourself")
	}

	// Verify receiver exists.
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, req.ReceiverID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("checking receiver: %w", err)
	}
	if !exists {
		return nil, errors.New("receiver not found")
	}

	m := &models.Message{}
	err := s.db.QueryRow(`
		INSERT INTO messages (sender_id, receiver_id, content)
		VALUES ($1, $2, $3)
		RETURNING id, sender_id, receiver_id, content, is_read, created_at`,
		senderID, req.ReceiverID, req.Content,
	).Scan(&m.ID, &m.SenderID, &m.ReceiverID, &m.Content, &m.IsRead, &m.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting message: %w", err)
	}
	return m, nil
}

// ListConversations returns the latest message per conversation partner for a user.
func (s *MessageService) ListConversations(userID string) ([]models.Conversation, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT ON (peer_id)
			peer_id,
			peer_name,
			content AS last_message,
			created_at AS last_message_time,
			unread_count
		FROM (
			SELECT
				CASE WHEN sender_id = $1 THEN receiver_id ELSE sender_id END AS peer_id,
				u.full_name AS peer_name,
				m.content,
				m.created_at,
				(SELECT COUNT(*) FROM messages
				 WHERE receiver_id = $1 AND sender_id = CASE WHEN m.sender_id = $1 THEN m.receiver_id ELSE m.sender_id END
				 AND is_read = FALSE) AS unread_count
			FROM messages m
			JOIN users u ON u.id = CASE WHEN m.sender_id = $1 THEN m.receiver_id ELSE m.sender_id END
			WHERE m.sender_id = $1 OR m.receiver_id = $1
			ORDER BY m.created_at DESC
		) sub
		ORDER BY peer_id, last_message_time DESC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing conversations: %w", err)
	}
	defer rows.Close()

	var convs []models.Conversation
	for rows.Next() {
		var c models.Conversation
		if err := rows.Scan(&c.PeerID, &c.PeerName, &c.LastMessage, &c.LastMessageTime, &c.UnreadCount); err != nil {
			return nil, err
		}
		convs = append(convs, c)
	}
	return convs, rows.Err()
}

// GetConversation returns all messages between two users, newest first.
func (s *MessageService) GetConversation(userID, peerID string, page, limit int) ([]models.Message, error) {
	offset := (page - 1) * limit
	rows, err := s.db.Query(`
		SELECT id, sender_id, receiver_id, content, is_read, created_at
		FROM messages
		WHERE (sender_id = $1 AND receiver_id = $2)
		   OR (sender_id = $2 AND receiver_id = $1)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4`, userID, peerID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("fetching conversation: %w", err)
	}
	defer rows.Close()

	var msgs []models.Message
	for rows.Next() {
		var m models.Message
		if err := rows.Scan(&m.ID, &m.SenderID, &m.ReceiverID, &m.Content, &m.IsRead, &m.CreatedAt); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// MarkRead marks a single message as read. Only the receiver may mark it.
func (s *MessageService) MarkRead(messageID, userID string) error {
	result, err := s.db.Exec(
		`UPDATE messages SET is_read = TRUE WHERE id = $1 AND receiver_id = $2`,
		messageID, userID,
	)
	if err != nil {
		return fmt.Errorf("marking message read: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return errors.New("message not found or not the receiver")
	}
	return nil
}
