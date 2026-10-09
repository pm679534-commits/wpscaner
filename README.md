# WordPress plugin təhlükəsizlik skaneri + Codex

Kali Linux-da WordPress.org-un populyar pluginlərini ZIP kimi yükləyir, açır və `semgrep scan --config p/wordpress` ilə statik analiz edir. İlk səhifədə tapıntı yoxdursa növbəti səhifəyə keçir; **ilk Semgrep tapıntısına qədər** davam edir. Tapıntı olmayan açılmış plugin qovluğu silinir; tapıntı və ya skan xətası olan qovluq saxlanılır. Arxivlər və hesabatlar saxlanılır. Tapıntı çıxanda skript eyni terminalda Codex CLI-nin interaktiv pəncərəsini ilkin tapşırıqla açır. Codex hesabatı və saxlanmış plugin kodunu oxuyur.

## Tələblər

- Kali Linux, Python 3.10+ və internet bağlantısı
- Əskik sistem paketlərini quraşdırmaq üçün `sudo` hüququ
- Codex CLI və bir dəfə ChatGPT hesabı ilə giriş; ayrıca OpenAI API açarı lazım deyil

Skript əvvəlcə `curl` və `unzip` yoxlayır; lazım olsa `apt-get` ilə quraşdırır. Semgrep yoxdursa, `~/.local/share/wp-plugin-scanner/venv` daxilində virtual mühit yaradıb `pip install semgrep` işlədir.

Codex üçün Kali-də birdəfəlik quraşdırma və giriş:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
codex
```

İlk `codex` açılışında “Sign in with ChatGPT” seçin. Quraşdırıcı `codex` əmrini PATH-ə əlavə etməyibsə, onun göstərdiyi PATH addımını yerinə yetirin. Brauzersiz mühitdə `codex login --device-auth` istifadə edə bilərsiniz.

## Kali-də işə salma

```bash
git clone <SIZIN_GITHUB_REPO_URL>
cd wp-plugin-scanner
python3 scanner.py
```

Başqa say və ya çıxış qovluğu:

```bash
python3 scanner.py --count 10    # hər səhifədə 10 plugin
python3 scanner.py --output "$HOME/Downloads/wp-audit-results"
python3 scanner.py --no-codex
```

Nəticələr `~/Downloads/wp-plugin-scan-results/<tarix>-<id>/` altında saxlanılır:

```text
archives/       yüklənmiş ZIP-lər
extracted/      tapıntılı və ya xətalı plugin kodu
report.txt      oxunaqlı hesabat
report.json     tam JSON/Semgrep nəticələri
```

## Codex qiymətləndirməsi

`python3 scanner.py` işə salındıqda populyar siyahı səhifə-səhifə skan edilir və ilk tapıntıda `codex --sandbox read-only --search "..."` avtomatik açılır. İlkin tapşırıqda tapıntının qısa xülasəsi var; tam məlumat `report.json`, `report.txt` və `extracted/` qovluğundadır. Codex terminalında əlavə suallar verə bilərsiniz. Bütün siyahı bitənə qədər tapıntı çıxmazsa skan dayanır və Codex açılmır. API eyni pluginləri təkrarlayarsa skan da təhlükəsiz şəkildə dayanır. `--no-codex` avtomatik açılışı söndürür.

Codex mövcud deyilsə skan hesabatı yenə saxlanılır və quraşdırma barədə xəta göstərilir. Codex-in cavabı təsdiqlənmiş boşluq və ya CVE sübutu deyil; versiyanı və rəsmi advisory/CVE qeydini ayrıca yoxlayın.

Skan statik analizdir: yanlış pozitiv və ötürülən boşluqlar mümkündür. Semgrep qaydalarının yüklənməsi üçün internet lazımdır. Skan xətası olduqda plugin təmiz sayılmır və açılmış qovluq saxlanılır. ZIP yolları, symlink-lər, fayl sayı və açılmış ölçü yoxlanılır; plugin kodu icra edilmir.

## GitHub-a yükləmə

GitHub-da `wp-plugin-scanner` adlı boş repo yaratdıqdan sonra bu qovluqda:

```bash
git init
git branch -M main
git add scanner.py README.md .gitignore tests/
git commit -m "Add WordPress plugin security scanner"
git remote add origin <SIZIN_GITHUB_REPO_URL>
git push -u origin main
```

Lokal yoxlama: `python3 -B -m unittest discover -s tests -v`. Bu testlər xarici xidmətlərə qoşulmur.
