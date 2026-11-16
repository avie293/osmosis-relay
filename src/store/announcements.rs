//! News the server operator sends to every player, typed into the server console. They are public, so unlike chat
//! messages they are stored as plain text.

use std::collections::VecDeque;

use super::{Store, now_millis};
use crate::protocol::Announcement;

const MAX_ANNOUNCEMENTS: usize = 50;
pub const MAX_ANNOUNCEMENT_LENGTH: usize = 1000;

impl Store {
    pub fn announcements(&self) -> &VecDeque<Announcement> {
        &self.announcements
    }

    pub fn announce(&mut self, text: String) -> Announcement {
        let time = self.announcements.back().map_or(now_millis(), |last| now_millis().max(last.time + 1));
        let announcement = Announcement { time, text };
        self.announcements.push_back(announcement.clone());
        if self.announcements.len() > MAX_ANNOUNCEMENTS {
            self.announcements.pop_front();
        }
        self.dirty = true;
        announcement
    }
}
