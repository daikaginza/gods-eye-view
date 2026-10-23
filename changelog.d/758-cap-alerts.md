- Serve official CAP emergency alerts from a server-side catalog of national
  publishers at `/api/cap`. The US National Weather Service is read from its
  GeoJSON alerts API in one request, so every active alert arrives instead of
  the first 32 linked documents, and an update whose original alert is no
  longer listed is still shown (Gustavo Beneduzi, Kevin Rajan, daikaginza,
  #758).
