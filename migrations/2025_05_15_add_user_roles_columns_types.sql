CREATE TYPE user_role AS ENUM ('user', 'admin');

-- 2. Add the column using the new enum type
ALTER TABLE users
ADD COLUMN role user_role DEFAULT 'user' NOT NULL;