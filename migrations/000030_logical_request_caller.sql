-- Caller attribution is observational, never a quota scope or trust input.
ALTER TABLE logical_requests ADD COLUMN caller_sdk text;
ALTER TABLE logical_requests ADD CONSTRAINT logical_requests_caller_sdk_valid
    CHECK (caller_sdk IS NULL OR caller_sdk IN ('ios', 'android', 'react-native', 'javascript'));
