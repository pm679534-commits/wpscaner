# WordPress plugin təhlükəsizlik skaneri

Kali Linux-da WordPress.org-un ən populyar pluginlərini ZIP kimi yükləyir, açır və `semgrep scan --config p/wordpress` ilə statik analiz edir. Tapıntı olmayan açılmış plugin qovluğu silinir; tapıntı və ya skan xətası olan qovluq saxlanılır. Arxivlər və hesabatlar saxlanılır.

## Tələblər

- Kali Linux, Python 3.10+ və internet bağlantısı
- Əskik sistem paketlərini quraşdırmaq üçün `sudo` hüququ
- İstəyə bağlı GPT analizi üçün OpenAI API açarı

Skript əvvəlcə `curl` və `unzip` yoxlayır; lazım olsa `apt-get` ilə quraşdırır. Semgrep yoxdursa, `~/.local/share/wp-plugin-scanner/venv` daxilində virtual mühit yaradıb `pip install semgrep` işlədir.

## Kali-də işə salma

```bash
git clone <SIZIN_GITHUB_REPO_URL>
cd wp-plugin-scanner
python3 scanner.py
```

Başqa say və ya çıxış qovluğu:

```bash
python3 scanner.py --count 10
python3 scanner.py --output "$HOME/Downloads/wp-audit-results"
```

Nəticələr `~/Downloads/wp-plugin-scan-results/<tarix>-<id>/` altında saxlanılır:

```text
archives/       yüklənmiş ZIP-lər
extracted/      tapıntılı və ya xətalı plugin kodu
report.txt      oxunaqlı hesabat
report.json     tam JSON/Semgrep nəticələri
```

## GPT qiymətləndirməsi

```bash
export OPENAI_API_KEY='sizin-api-akariniz'
python3 scanner.py --llm --model gpt-5.5
```

`--llm` hər tapıntının kod kontekstini OpenAI Responses API-yə göndərir. API istifadəsi ödənişli ola bilər. Açarı repoya əlavə etməyin. Model cavabı təsdiqlənmiş zəiflik və ya CVE sübutu deyil; CVE üçün versiyanı və rəsmi advisory/CVE qeydini ayrıca yoxlayın.

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
