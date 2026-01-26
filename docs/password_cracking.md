# Password Cracking

Password cracking is more of an art than a science, with a healthy dose of luck thrown in. SteppingStones provides some
downloadable files which can be used with `hashcat` to possibly find more passwords than a simple 3rd party wordlist
& rule collection. Strategies for using these files are show in the tips below...

## Custom Wordlists

### -a 0

#### Wordlist From All Sources

SteppingStones provides a wordlist which contains words extracted from known secrets, usernames and systems in the
credentials table, along with full names, roles and descriptions extracted from any attached BloodHound instances.

:::{tip}
Use this full wordlist with a large rule set (`-r`) to help identify accounts with (variations of) the password set to the username or exposed
in the description in AD.
:::

:::{tip}
Everytime a rule list is used, add `--loopback` to apply the same set of rules against any new passwords too.
:::

#### Known Secrets Only

Certain attacks work best when working exclusively with password data and not the wider range of words in the "all 
sources" wordlist. For these you can download just the known secrets.

:::{tip}
This wordlist can be useful for quickly syncing up with other teammates working on the same set of hashes.
:::

### -a 1

Parts of Known Secrets are strings of letters or numbers or symbols which make up part of known passwords. These parts
can be stuck back together with each other via a combinator attack to form the original and (more importantly) new 
passwords to try.

:::{tip}
Hashcat's builtin support for combinator attacks are relatively feature limited, only supporting two wordlists and a single rule
for each list. (e.g. `-j "$@"`). It is however very fast and recombining parts by specifying the parts wordlist twice, 
or combining with an unrelated wordlist can yield some quick wins. 
:::

:::{tip}
To work around hashcat's rule limitation with `-a 1` you can use `combinator.exe` in hashcat_utils to stitch together
the parts and pipe them into hashcat via stdin operating in `-a 0` mode which allows the `-r` rule list parameter.  
:::

:::{tip}
To build passwords made of every possible combination of three parts you can use the above technique and the 
"Parts of Known Secrets -> Append Rules" instead of, or as well as, a (small) generic rulelist.

```
combinator.exe parts-wordlist-20260122-150031.txt parts-wordlist-20260122-150031.txt | hashcat -O -a 1 -m 1000 -r parts-append-20260122-145943.rule -r HashMob._100.rule hashes-1000-20260122-151723.txt
```
:::

:::{tip}
The parts list works especially well with PRINCE attacks. Using [pp64.exe](https://github.com/hashcat/princeprocessor) 
to combine varying numbers of parts until the password length requirements are met. The output of pp64.exe must be piped 
into hashcat, which allows for combination with rulelists to generate further candidates and prevent stdin from being
a bottleneck.

The parts wordlist is served up shuffled so if you need to stop the PRINCE attack you can restart it with a freshly 
downloaded wordlist to avoid going over the same set of candidates. 

```
pp64.exe --pw-min=15 --pw-max=20 < parts-wordlist-20260121-223721.txt | hashcat -O -m 1000 -a 0 -r HashMob.50k.rule hashes-1000-20260112-113226.txt
```
:::

### -a 6 & -a 7

The `-a 6` (prefix wordlist & suffix masks) and the `-a 7` (prefix masks & suffix wordlist) attacks both require a pair of files. The 
file for each half of the attack can be found in the Wordlist and Masklist menus accordingly.

:::{tip}
Users typically pad their passwords to required lengths with additional digits and symbols on the end, so its typical 
for the `-a 6` attack to be more productive than the `-a 7` attack :::

The wordlists are constructed by removing leading/trailing numbers and suffixes from known secrets. 

:::{tip}
You may also find success by simply using these wordlists in a combinator attack (`-a 0`) with a public password list.
Using the suffix list for the left-hand side of the combinator (and vice versa) is also fair game.
Although combinator attacks can't be used with full rule lists, a single rule to add a symbol at the join 
(e.g. `-j "$@"` to add an `@` at the join) is also effective.
:::

The mask lists are 
produced by simplifying the removed strings of digits and symbols into their hashcat mask versions. These masks are then
ordered using a combination of keyspace and frequency to produce a prioritised list of masks which should yeild the most
results quickly with diminishing returns.

:::{tip}
The priority ordering of the mask lists means you will reach a point where the attacks feel too slow given their yield.
This is by design and its OK to quit the attack at this point.

At this point, you want to remove the already evaluated masks from the mask list (note the `Guess.Queue.Mod` in the 
hashcat output to know how many lines to remove) and continue the attack with a non-exhaustive search using `-t`. A
parameter of `-t 10` will still check all digits but will speed up the attack by skipping unlikely symbols.
:::


