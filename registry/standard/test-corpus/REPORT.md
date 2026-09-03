<!-- Historical document (15.08.2026, German) — the generation record
     of the test corpus; kept verbatim as evidence, E20 legacy-exempt
     like sealed quotations (classification: assignment R, report §27). -->

# Registry-Erst-Einträge — Erzeugungsreport (2026-08-15)

19 Manifeste aus den Recherche-Daten (5 Cluster) erzeugt. Alle Dateien `jq`-geprüft (Syntax) plus struktureller Schema-Check (Pflichtfelder, erlaubte Felder, Interface-/Auth-Enums, IRI-Muster): 19/19 OK. Nur verifizierte Interfaces übernommen; alle Interfaces sind zustandslose Navigation/Suche/Downloads → `tier: "base"`.

## Erzeugte Einträge

| Slug | Publisher-Slug | Interfaces | Verifikationsstand |
|---|---|---|---|
| fedlex-jolux-sparql | ch-bundeskanzlei | Sparql | Testquery + bounded Query (15.08.2026) |
| termdat-lindas | ch-bundeskanzlei | Sparql, Rest | SPARQL-Query + LD-Dereferenzierung geprüft |
| entscheidsuche-api | verein-entscheidsuche | Rest, Download, Mcp | alle 3 Endpunkte live geprüft (MCP: 5 Tools) |
| amtsdruckschriften-bar | ch-bundesarchiv | Download | Seite erreichbar; nur Web-UI, keine API |
| lindas-sparql | ch-bundesarchiv | Sparql | GET+POST Testquery, HTTP 200 |
| bfs-stattab-pxweb | ch-bfs | Rest ×2 | PxWeb (Liste/Meta/Daten) + DAM-API geprüft |
| visualize-admin-graphql | ch-bafu | Rest (GraphQL) | Introspektions-POST HTTP 200 |
| lindas-gemeindeverzeichnis-historisiert | ch-bfs | Sparql, Download | Graph-COUNT + URI-Dereferenzierung (Turtle) |
| opendata-swiss-ckan | ch-bfs | Rest | package_search/status_show geprüft |
| opendata-swiss-dcat | ch-bfs | Download ×3 | catalog.xml/.ttl/.jsonld HTTP 200, paginiert |
| i14y-public-api | ch-bfs | Rest, Download | concepts/catalogs + DCAT-Export (ttl/rdf) geprüft |
| geo-admin-stac-api | ch-swisstopo | Rest, Download | STAC-Root + /collections geprüft |
| geo-admin-wms-wmts | ch-swisstopo | Rest ×2 | beide GetCapabilities valide |
| geo-admin-rest-api | ch-swisstopo | Rest | SearchServer-JSON geprüft |
| swisstopo-ogd-downloads | ch-swisstopo | Download, Rest | Portal + swissALTI3D-Collection geprüft |
| opentransportdata-swiss | ch-bav | Rest (apikey) | /ojp20: HTTP 403 ohne Key = erwartetes Verhalten |
| meteoschweiz-ogd | ch-meteoschweiz | Rest, Download | STAC-Root + Collection ogd-smn abgerufen |
| zefix-shab | ch-ehra | Rest ×2 | Zefix: OpenAPI + 401 erwartbar; SHAB: Live-JSON |
| transport-opendata-ch | opendata-ch | Rest | /v1/locations live geprüft |

## Lizenz-Klärungsfälle

Gesetzte URI = beste Annäherung, KEINE bestätigte offizielle Lizenzangabe:

1. **fedlex-jolux-sparql** — `terms_open`; Lizenzseite fedlex.admin.ch/de/broadcasters (SPA) maschinell nicht prüfbar, Angabe stützt sich auf lindas.admin.ch/data-usage/fedlex/ («amtliches Werk, Art. 5 URG»).
2. **termdat-lindas** — `terms_open`; Dataset-Metadaten nennen KEINE Lizenz (nur admin.ch-Rechtshinweise, amtliches Werk). Vor Verzeichnisaufnahme bei der BK klären.
3. **entscheidsuche-api** — `terms_open`; keine formale Lizenz (amtliche Werke, Art. 5 URG); Quellenangabe erbeten, Spende bei kommerzieller Nutzung erwünscht (keine Rechtspflicht).
4. **amtsdruckschriften-bar** — `terms_open`; keine explizite Lizenz, Rechtshinweise-Seite lieferte HTTP 403 (Bot-Schutz), nicht wörtlich geprüft.
5. **lindas-sparql** — `terms_open`; LINDAS hat keine Einheitslizenz, Lizenz gilt je Datensatz. Angabe bezieht sich auf den offenen Dienst-Zugang.
6. **visualize-admin-graphql** — `terms_open`; Datenlizenz je Cube (LINDAS-Metadaten); die Software selbst ist BSD-3-Clause (nicht ins Manifest übernommen, da Datendienst).
7. **opendata-swiss-ckan / opendata-swiss-dcat** — Nutzungsbedingungs-URL `https://opendata.swiss/de/terms-of-use` statt Lizenz-URI: vier OGD-Nutzungsvarianten je Datensatz, keine Einheitslizenz.
8. **i14y-public-api** — `terms_open`; keine explizite Einheitslizenz, Fair-Use-Vorbehalt, Rahmen EMBAG.
9. **zefix-shab** — `terms_by`; Zefix ohne explizite Lizenz auf der Website (DCAT-Metadaten LINDAS: «Provide-the-Source»); Lizenzlage des SHAB-Teils (SECO) ungeklärt.
10. **transport-opendata-ch** — KEINE Lizenz vorhanden; als URI die Doku-Seite `https://transport.opendata.ch/docs.html` gesetzt (dort stehen die Nutzungshinweise). Daten stammen von timetable.search.ch, deren Bedingungen gelten. Deutlichster Klärungsfall.

Hinweise (geringerer Klärungsbedarf):
- **swisstopo-ogd-downloads** — `license` ist die swisstopo-OGD-Nutzungsbedingungs-URL statt einer Lizenz-URI (gleiches Muster wie opendata.swiss-Terms; nachgetragen 18.08. aus der Konsistenzprüfung).
- **meteoschweiz-ogd** — STAC sagt wörtlich «CC-BY» ohne Version; CC BY 4.0 als URI angenommen.
- **geo-admin-stac-api** — `terms_by` für die BGDI-Bedingungen; zusätzlich Lizenz je Collection im STAC-Feld `license` (z. B. CC-BY, «proprietary» = swisstopo-OGD-Bedingungen).
- **geo-admin-wms-wmts / geo-admin-rest-api** — BGDI-Nutzungsbedingungen («Quellenangabe Pflicht») auf `terms_by` abgebildet; WMS-Capabilities melden Fees/AccessConstraints = none.
- **bfs-stattab-pxweb** — DAM-Code «OPEN-BY» sauber auf `terms_by` abbildbar (kein Klärungsfall).
- **opentransportdata-swiss** — eigene «Terms of Use Open Data» (offizielle URL gesetzt), bewusst keine Standard-Lizenz (kein CC).

## Weggelassene / unverifizierte Kandidaten

- **opentransportdata-swiss → `https://api.opentransportdata.swiss/ojp2020`** (Rest, OJP 1.0): `verifiziert=false` — URL nur aus dem Cookbook, nicht selbst abgerufen. Einziges unverifiziertes Interface; weggelassen.
- Ganze Einträge wurden keine weggelassen: alle 19 Recherche-Einträge haben mindestens ein verifiziertes Interface.

## Org-Slug-Zuordnung

| Org-Slug | Organisation (laut Recherche) |
|---|---|
| ch-bundeskanzlei | Schweizerische Bundeskanzlei (BK; inkl. Sektion Terminologie) |
| ch-bundesarchiv | Schweizerisches Bundesarchiv (BAR; auch LINDAS-Betrieb) |
| ch-bfs | Bundesamt für Statistik (BFS; inkl. Geschäftsstelle OGD, Kompetenzzentrum Datenbewirtschaftung) |
| ch-bafu | Bundesamt für Umwelt (BAFU; «und weitere Bundesbehörden» bei visualize.admin.ch) |
| ch-swisstopo | Bundesamt für Landestopografie swisstopo (inkl. BGDI) |
| ch-bav | Bundesamt für Verkehr (BAV); Plattform-Betrieb durch SBB im Auftrag des BAV |
| ch-meteoschweiz | Bundesamt für Meteorologie und Klimatologie MeteoSchweiz |
| ch-ehra | Eidg. Amt für das Handelsregister EHRA / Bundesamt für Justiz; SHAB-Interface: SECO (Amtsblattportal) — ggf. späteren Zweit-Publisher klären |
| verein-entscheidsuche | Verein entscheidsuche.ch |
| opendata-ch | Verein Opendata.ch (Community) |

## Weitere Auffälligkeiten

- **i14y-public-api**: DCAT-Export braucht eine konkrete Katalog-ID (URI-Templates sind keine gültigen Endpunkt-URIs — von `oh-validate` beanstandet, 15.08.); Manifest zeigt jetzt auf den verifizierten swisstopo-Katalog-Export (`…/catalogs/8ec39bcd-…/dcat/exports/ttl`), das Template-Muster steht in der verlinkten Doku; Formate ttl/rdf OK, xml/jsonld → HTTP 400.
- **lindas-sparql vs. Web-UI**: `https://lindas.admin.ch/sparql` ist NICHT der Maschinen-Endpunkt (302 auf YASGUI); Manifest nutzt korrekt `/query`.
- **opendata.swiss**: Haupthost blockiert manche Bots (403); Clients direkt `ckan.opendata.swiss` verwenden. Nachfolgeportal «opendata.swiss next» angekündigt — CKAN-API könnte abgelöst werden.
- **fedlex-jolux-sparql** überschneidet sich bewusst mit dem Beispiel `standard/examples/fedlex-sparql.json` (anderer Slug/@id); Überschneidung geo-admin-stac-api ↔ swisstopo-ogd-downloads ist laut Recherche beabsichtigt (generische API vs. OGD-Bestand).
- **geo-admin-wms-wmts**: OGC WMS/WMTS (HTTP/KVP) mangels eigenem Interface-Typ als `RestInterface` erfasst.
- **lindas-gemeindeverzeichnis-historisiert**: Download-Endpunkt ist eine Beispiel-URI (Muster `https://ld.admin.ch/municipality/{BFS-Nr}`, Beispiel 261 = Zürich).
