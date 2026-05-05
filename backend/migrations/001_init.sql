--extensions
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
-- Note: Using gen_random_uuid() from pgcrypto extension instead of gen_random_uuid()
-- pgcrypto is built-in and provides gen_random_uuid()

--User table capture details of medical professionals, including verification status, specialty, and profile information
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    country TEXT NOT NULL,
    specialty TEXT,
    bio TEXT,
    profile_image_url TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_specialty ON users(specialty);
CREATE INDEX idx_users_country ON users(country);

--Verification table for medical license verification
CREATE TABLE verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    license_number TEXT NOT NULL,
    document_url TEXT NOT NULL,
    status TEXT CHECK (status IN ('pending','approved','rejected')) DEFAULT 'pending',
    reviewed_by UUID,
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_verifications_user_id ON verifications(user_id);
CREATE INDEX idx_verifications_status ON verifications(status);

-- Organizations table for medical institutions, hospitals, etc.
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    country TEXT,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- User_organizations table to manage many-to-many relationship between users and organizations, with role (e.g., member, admin)
CREATE TABLE user_organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    role TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_user_org_user ON user_organizations(user_id);
CREATE INDEX idx_user_org_org ON user_organizations(organization_id);

--Cases table to store medical cases shared by users, with fields for title, description, specialty tag, anonymization status, and engagement metrics (views, comments)
CREATE TABLE cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    specialty_tag TEXT,
    is_anonymized BOOLEAN NOT NULL DEFAULT FALSE,
    views_count INT DEFAULT 0,
    comments_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_cases_user_id ON cases(user_id);
CREATE INDEX idx_cases_specialty ON cases(specialty_tag);
CREATE INDEX idx_cases_created_at ON cases(created_at DESC);

--Case_media table to store media files (images, videos) associated with cases, with reference to the case and file metadata
CREATE TABLE case_media (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    file_url TEXT NOT NULL,
    file_type TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_case_media_case_id ON case_media(case_id);

--Comments table to store comments on cases, with reference to the case, user, content, and timestamp
CREATE TABLE comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_comments_case_id ON comments(case_id);
CREATE INDEX idx_comments_user_id ON comments(user_id);
CREATE INDEX idx_comments_created_at ON comments(created_at DESC);

--Messages table to store private messages between users, with reference to sender, receiver, content, read status, and timestamp
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
    receiver_id UUID REFERENCES users(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_messages_sender ON messages(sender_id);
CREATE INDEX idx_messages_receiver ON messages(receiver_id);
CREATE INDEX idx_messages_conversation ON messages(sender_id, receiver_id, created_at DESC);

-- Notifications table to store notifications for users, with reference to the user, type of notification, related case or message, read status, and timestamp
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    reference_id UUID,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_read ON notifications(is_read);

-- Follows table to manage user follow relationships, with reference to follower and following users, and timestamp
CREATE TABLE follows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    follower_id UUID REFERENCES users(id) ON DELETE CASCADE,
    following_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(follower_id, following_id)
);

-- Research table to store research articles or resources shared by users, with fields for title, description, link, specialty tag, and engagement metrics (views, comments)
CREATE TABLE research (
    id UUID PRIMARY KEY DEFAULT
CREATE INDEX idx_users_name_search ON users USING gin (full_name gin_trgm_ops);
CREATE INDEX idx_cases_title_search ON cases USING gin (title gin_trgm_ops);
);
--Aud logs table to store audit logs for user actions, with reference to the user, action performed, metadata, and timestamp
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    action TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
