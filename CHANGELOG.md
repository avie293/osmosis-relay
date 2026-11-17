# Changelog

## Unreleased

### Added
- Added Minecraft account verification through the Mojang session server
- Added friend lists, friend requests and online status
- Added an offline mode for local testing
- Added relaying and storage of end-to-end encrypted chat messages, including messages to offline friends, the
  last 500 messages per conversation and unread counts
- Added blocking players, which ends the friendship and hides the blocker from the blocked player
- Added deleting a chat for yourself while the other side keeps it
- Added group chats of up to 10 members, managed by the group owner
- Added world hosting: friends see who is hosting, hosts invite friends or group members, and invited players join
  through a tunnel port that relays the connection
- Added remembering invites per world, so invited players can join again whenever the host opens that world
- Added announcements, sent with the `announce` console command and stored for players who log in later
- Added when friends were last online and the newest message of each chat to the login data, for chat list previews
- Added listing, adding and removing the members of a world, also while it is not hosted
- Added sharing resource packs with the guests of a hosted world, sent from the host through the tunnel port
