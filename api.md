endpoint: /api/messages\
parameters:
- oldest_id:\
Type: str | None\
Default: None\
Description: The id of the oldest message currently available.\
- n:\
Type: int | None\
Default: 50\'
Description: How many messages to be sent back.
- chat_id:\
Type: int

description: Fetch messages before the oldest message, if there are no messages available yet, it'll fetch the most recent ones.
