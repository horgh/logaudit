--
-- Setup:
--
-- createdb -E UTF8 --locale=en_CA.UTF-8 --template=template0 log
-- createuser -P log
-- psql and insert schema.
--

CREATE TABLE log_line (
  id SERIAL NOT NULL,
  hostname VARCHAR NOT NULL,
  filename VARCHAR NOT NULL,
  -- As there could be binary data.
  line BYTEA NOT NULL,
  time TIMESTAMP WITH TIME ZONE NOT NULL,
  create_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  PRIMARY KEY (id)
);

-- The below method for avoiding duplicates is too slow.

--CREATE FUNCTION bi_log_line()
--RETURNS TRIGGER AS $$
--BEGIN
--  PERFORM FROM log_line WHERE hostname = NEW.hostname AND
--    filename = NEW.filename AND
--    line = NEW.line AND
--    time = NEW.TIME;
--  IF FOUND THEN
--    -- Don't insert.
--    RETURN NULL;
--  END IF;
--  RETURN NEW;
--END
--$$
--LANGUAGE plpgsql;
--
--CREATE TRIGGER bi_log_line
--BEFORE INSERT ON log_line
--FOR EACH ROW EXECUTE PROCEDURE bi_log_line()

CREATE TABLE host (
  id SERIAL NOT NULL,
  hostname VARCHAR NOT NULL,
  create_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  audited_until TIMESTAMP WITH TIME ZONE NOT NULL,
  PRIMARY KEY (id),
  UNIQUE (hostname)
);

-- I add the host table after having log lines. Start out with every host in
-- there and having audited up until this moment.
INSERT INTO host
(hostname, audited_until)
SELECT DISTINCT hostname, NOW() FROM log_line;
