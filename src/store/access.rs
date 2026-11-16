//! Who may join which hosted world. An invite is remembered, so the guest can come back whenever the host opens the
//! same world again. Ending the friendship or blocking forgets it.

use std::collections::HashSet;

use super::Store;
use crate::protocol::{Uuid, WorldId};

impl Store {
    pub fn allowed_guests(&self, host: Uuid, world: WorldId) -> HashSet<Uuid> {
        self.world_access.get(&(host, world)).cloned().unwrap_or_default()
    }

    pub fn allow_guest(&mut self, host: Uuid, world: WorldId, guest: Uuid) {
        if self.world_access.entry((host, world)).or_default().insert(guest) {
            self.dirty = true;
        }
    }

    /// Forgets every invite between these two players, in both directions.
    pub(super) fn forget_access(&mut self, a: Uuid, b: Uuid) {
        let mut changed = false;
        self.world_access.retain(|&(host, _), guests| {
            if host == a {
                changed |= guests.remove(&b);
            } else if host == b {
                changed |= guests.remove(&a);
            }
            !guests.is_empty()
        });
        self.dirty |= changed;
    }
}
