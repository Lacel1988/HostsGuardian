# Atomic index replacement

Build a complete new corpus snapshot before replacing the active local index. A failed rebuild must preserve the previous usable snapshot. Model identity, embedding dimensions and corpus version must match. Deleting a document from the approved source manifest removes its chunks during the next complete rebuild.
