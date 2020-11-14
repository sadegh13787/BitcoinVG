Bitcoin Virtual Gold (VG) Core integration/staging tree
=====================================

http://www.BitcoinVG.com

What is Bitcoin Virtual Gold?
----------------

Bitcoin Virtual Gold (BVG) improves upon Bitcoin by putting the best chain in the hands of the users, 
not only the miners. Bitcoin VG is the first crypto currency to incorporate "Proof of Transaction" (PoT) as a 
way to have the best chain "Follow the money". Rather then let the ASICs choose the best chain based on the 
amount of hash work, Bitcoin VG adds the PoT feature to embed the amount of vouts in a block. The amount of 
transaction output volume is captured in the block's hash. This serves as a proof (in the header) that the 
block contains the specified amount of transactional volume. The best chain can now combine the PoW and PoT 
metrics to follow the best chain. More transactional volume in a block means the PoT metric becomes higher. 
Higher transactional block volume makes it much harder to perform a 51% attack on the network because the 
attacker must also have a significant amount of coin to perform the attack. This menas that the attacker 
would be competing with the community on the amount of coin that is held in each block. Given that the 
community will generally hold more coin than the attacker, we can assume that if there are transactions 
every block with an average amount of community coin volume, then the attacker will never be able to 
attack the blockchain because the attacker's coin volume would not allow enough work to form a new chain.

Bitcoin Virtual Gold is a brand new innovation for the blockchain and its PoT feature may be considered to 
become part of the Bitcoin Improvement Propoasl (BIP) in the future. Given that BVG is new, it will still
be vulneralbe to 51% attacks until it becomes more mature. The lack of volume and price of a new crypto
makes it vulneralbe to the early users who wish to accumulate much coin to do harm. As BVG becomes mature,
its price would rise and block volume would become filled with transactions every block. This would allow
the PoT metric to have a non-zero value on every block and thus keeping the main chain adapting towards
the blocks with the greatest money flow not the most mining power. 4.67% of the 21 Million total supply 
has been mined at block #1 with the intent to keep the chain protected by artificially keeping the PoT 
metric higher until more natural volume starts to occur in the future.


Bitcoin Virtual Gold is built on Bitcoin.
Bitcoin is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Bitcoin Core is the name of open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Bitcoin Core software, see https://bitcoincore.org/en/download/, or read the
[original whitepaper](https://bitcoincore.org/bitcoin.pdf).

License
-------

Bitcoin VG Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/BitcoinVG/BitcoinVG/tags) are created
regularly to indicate new official, stable release versions of BitcoinVG Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.
Translations
------------

Changes to translations as well as new translations can be submitted to
[Bitcoin Core's Transifex page](https://www.transifex.com/bitcoin/bitcoin/).

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.

Translators should also subscribe to the [mailing list](https://groups.google.com/forum/#!forum/bitcoin-translators).