CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  phone TEXT,
  password_hash TEXT NOT NULL,
  account_type TEXT NOT NULL DEFAULT 'creator' CHECK (account_type IN ('creator','shop')),
  shop_name TEXT,
  shop_details JSONB NOT NULL DEFAULT '{}'::jsonb,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
  wallet_balance NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (wallet_balance >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id),
  type TEXT NOT NULL CHECK (type IN ('donation','deposit','withdrawal','adjustment')),
  amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','cancelled','completed')),
  method TEXT,
  reference TEXT,
  note TEXT,
  processed_by BIGINT REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS transactions_user_created_idx ON transactions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS transactions_status_created_idx ON transactions(status, created_at DESC);

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO platform_settings(key,value) VALUES
 ('platform_name','"Bangla Super Chat"'::jsonb),
 ('commission_percent','10'::jsonb),
 ('min_withdrawal','300'::jsonb),
 ('payment_methods','["bKash","Nagad","Rocket","Upay","Bank Transfer"]'::jsonb)
ON CONFLICT (key) DO NOTHING;
