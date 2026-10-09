# WordPress plugin təhlükəsizlik skaneri + Codex

Kali Linux-da WordPress.org-un populyar pluginlərini ZIP kimi yükləyir, açır və `semgrep scan --config p/wordpress --config p/php` ilə statik analiz edir. Semgrep tapıntısı çıxanda Codex onu kod kontekstində yoxlayıb strukturlaşdırılmış qərar qaytarır. Yanlış pozitivdirsə skript növbəti pluginə keçir; ehtimal olunan boşluq və ya qeyri-müəyyən nəticə varsa saxlanmış kodla interaktiv Codex açılır. Təmiz və yanlış pozitiv nəticələr növbəti işə salmada təkrar skan edilmir.

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
python3 scanner.py --rescan      # əvvəl yoxlanan versiyaları da skan et
```

Nəticələr `~/Downloads/wp-plugin-scan-results/<tarix>-<id>/` altında saxlanılır:

```text
archives/       yüklənmiş ZIP-lər
extracted/      tapıntılı və ya xətalı plugin kodu
report.txt      oxunaqlı hesabat
report.json     tam JSON/Semgrep nəticələri
codex-review-*.json  Codex-in plugin üzrə qərarı (tapıntı varsa)
```

`~/Downloads/wp-plugin-scan-results/progress.json` təmiz və yanlış pozitiv pluginlərin `slug@version` qeydini saxlayır. Eyni versiya növbəti işə salmada atlanır; yeni versiya skan edilir. `--rescan` yadda saxlanmış versiyaları da yenidən yoxlayır.

## Codex qiymətləndirməsi

`python3 scanner.py` populyar siyahını səhifə-səhifə skan edir. Tapıntılı plugin üçün `codex exec` JSON qərarı yaradır: `false_positive` nəticəsində açılmış qovluq silinir və skan davam edir; `likely_vulnerability` və `needs_review` nəticəsində kod saxlanılır, interaktiv `codex` açılır. Skan və Codex qərarları hesabatda qalır. Bütün kataloq bitərsə və ya API yalnız təkrar pluginləri qaytararsa skan dayanır. `--no-codex` əvvəlki kimi ilk Semgrep tapıntısında dayanır və Codex-i işə salmır.

Codex mövcud deyilsə skan hesabatı yenə saxlanılır və quraşdırma barədə xəta göstərilir. Codex-in cavabı təsdiqlənmiş boşluq və ya CVE sübutu deyil; versiyanı və rəsmi advisory/CVE qeydini ayrıca yoxlayın.

Skan statik analizdir: yanlış pozitiv və ötürülən boşluqlar mümkündür. Semgrep qaydalarının yüklənməsi üçün internet lazımdır. Skan xətası olduqda plugin təmiz sayılmır və açılmış qovluq saxlanılır. PHP faylları olduğu halda Semgrep sıfır fayl skan edərsə, skript diaqnostikanı hesabatda saxlayıb dayanır. ZIP yolları, symlink-lər, fayl sayı və açılmış ölçü yoxlanılır; plugin kodu icra edilmir.

## GitHub-a yükləmə

GitHub-da `wp-plugin-scanner` adlı boş repo yaratdıqdan sonra bu qovluqda:

```bash
git init
git branch -M main
git add scanner.py codex-verdict.schema.json README.md .gitignore tests/
git commit -m "Add WordPress plugin security scanner"
git remote add origin <SIZIN_GITHUB_REPO_URL>
git push -u origin main
```

Lokal yoxlama: `python3 -B -m unittest discover -s tests -v`. Bu testlər xarici xidmətlərə qoşulmur.
