# Films, parked

The site does not publish these yet. Narration for Finnish and Swedish is in `docs/videos/narration/`. German, Spanish, Russian and French were never recorded. When the films come back, put them on a Videos page in every site language and point only the Swedish page at the Swedish files. The other pages used the Finnish films and said so.

## The five films

| File | Subject | Length to aim for |
| --- | --- | --- |
| `kenelle.mp4` | Who it is for | About half a minute |
| `tausta.mp4` | Blocks, compression, encryption, a peer first | Longer. The draft narration is about 1 min 45 s |
| `kayttoliittyma.mp4` | The interface | About half a minute |
| `komentorivi.mp4` | The command line | About half a minute |
| `mittaukset.mp4` | The Resilio Sync measurements | Longer. The draft narration is about 2 min 30–50 s |

Technical films should stay long. The short ones can stay short.

## Picture

1280×720, 12 frames a second, H.264 and AAC. A woman stands in the corner, because both voices below are women. Two drawings of the same person: mouth closed, and mouth slightly open. Swap to the open mouth while the waveform is loud.

Each film is a sequence of scenes, one per sentence of the on-screen caption. The scene changes on an even slice of the narration. The caption sits under the picture in the language of that film.

What each scene showed:

- Who it is for: the desktop Overview, the "where your data is" picture, the phone Files screen (`mobile-dark.png`, not the Android overview shots — those contain a "Pixel Launcher isn't responding" dialog), a short terminal card ("no account"), then the alpha banner cropped from Overview.
- Underneath: a file split into blocks, a block that shrinks and is then sealed, the "where your data is" picture, and a device → peer → storage diagram.
- Interface: Overview, the desktop Files page cropped so the right-hand analysis column is out of frame (that column still mentioned an assistant), the "where your data is" picture, the phone Files screen, and six example words (`metsä avain ilta kivi polku lasi` — an illustration, not a real fingerprint).
- Command line: one terminal card per command (`folder add`, `sync`, `share request`, `share create`, `update --daily` and `service install`).
- Measurements: a two-bar chart, Varsto against Resilio Sync. The chart titles stay language-neutral (`10 000 · s`, `2 × 1 GiB · s`, `log · MB`, `log · s`, `dup · s`, `2 · s`, `rename · MB`, `cut · s`, `cut · MB`). The spoken caption carries the sentence.

Do not use a screenshot that mentions an MCP server. That server was removed.

## Voices

Finnish: `fi-FI-NooraNeural`. The only other free Finnish neural voice on that service is `fi-FI-HarriNeural`, and he is a man, so he does not match the drawing. Swedish: `sv-SE-SofieNeural`.

Speech was generated with edge-tts and muxed in ffmpeg (`libx264`, `yuv420p`, CRF 26, AAC 96k, `+faststart`).

## Numbers the measurement film speaks

Paris to Amsterdam, 10 November 2026, two runs, median. The clock starts when the reader begins to fetch.

| Case | Varsto | Resilio Sync |
| --- | --- | --- |
| 10 000 small files | 25 s, about 292 MB | 25 s, about 313 MB |
| Two 1 GiB files | 44 s | 90 s |
| Log text | 17 s, 169 MB | 47 s, 563 MB |
| Duplicates | 13 s, 419 MB | 62 s, 856 MB |
| Two readers, slower city | about 118 s | about 118 s |
| A small change inside a large directory | 12 s, one good run, 26 MB | 15 s, 12 MB, from the 8 November run |
| A directory renamed | 10 s, no file data resent | 67 s, 1 269 MB, from the 8 November run |
| 100 Mbit/s, 40 ms, 1% loss, and the link cut for 0.3 s every 4 s | 432 s, about 336 MB | 934 s, about 328 MB |

SSH was left alone during the cuts. Say in the film that the two Resilio figures for the change and the rename are from the earlier run.

## Putting them back on the site

Add `Videos` after Screenshots in `NAV` and in the Learn footer group in `website/build.py`, with the labels already used once: fi Videot, sv Videor, fr Vidéos, de Videos, es Vídeos, ru Видео. A page per language. Finnish files at `assets/video/`, Swedish files at `assets/video/sv/`. The page that is not Finnish or Swedish should embed the Finnish films and say the narration is Finnish. Allow `media-src 'self'` if the site policy still omits it.
