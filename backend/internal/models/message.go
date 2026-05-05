package models

import "time"

// Message represents a row in the messages table.
type Message struct {
	ID         string    `json:"id"`
	SenderID   string    `json:"sender_id"`
	ReceiverID string    `json:"receiver_id"`
	Content    string    `json:"content"`
	IsRead     bool      `json:"is_read"`
	CreatedAt  time.Time `json:"created_at"`
}

// SendMessageRequest is the payload for POST /messages.
type SendMessageRequest struct {
	ReceiverID string `json:"receiver_id"`
	Content    string `json:"content"`
}

// Conversation is a summary of the latest message with a given peer.
type Conversation struct {
	PeerID          string    `json:"peer_id"`
	PeerName        string    `json:"peer_name"`
	LastMessage     string    `json:"last_message"`
	LastMessageTime time.Time `json:"last_message_time"`
	UnreadCount     int       `json:"unread_count"`
}
