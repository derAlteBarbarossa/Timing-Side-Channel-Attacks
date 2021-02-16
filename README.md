# Timing Side-Channel Attacks

**Discalimer1**: This repository is my implementation of the 3rd homwwork for the **Hardware Security** course at ETHZ. If you are taking this course, please don't go further.

**Disclaimer2**: The encrpytion library is not my own work. All rights shall be reserved for the authors.


The goal of this assignment is to leak the private key used to encrypt the
secret from the cache. Herbert wrote his own encryption library called hjbcrypt
to sign data with. We can sign our own data using hjb_sign_data(), which is
publicly available. Of course, encryption is a slow process, so Herbert used
lookup tables to accelerate the encryption process.
Moreover, while trying to further optimize the encryption he misunderstood the
inner workings of CPU caches and he thought that cacheline-sized entries for
these tables would have improved performances. Little did Herbert know that
depending on the table's index, a different cache line gets loaded to the
table. Therefore, his cache optimization only optimizes the side-channel.

The assignment has 3 stages:
 * Stage 1: FLUSH+RELOAD
 * Stage 2: EVICT+RELOAD
 * Stage 3: Hardened crypto (more details down)

## Stage 1: FLUSH + RELOAD

The first step of this assignment is to implement a FLUSH + RELOAD attack.
This attack consists in (i) flushing the content of the table from the caches,
then (ii) calling hjb_sign_data() and finally (iii) reloading the cache lines
while timing the accesses to verify which one was already loaded by
hjb_sign_data().

You can do this in two ways:
 1. FLUSH + RELOAD the whole table
 2. FLUSH + RELOAD a single entry (e.g., table[0]).

### FLUSH + RELOAD v.1

Flushing the entire table is conceptually the simplest attack you can perform;
every single byte from the key will be used to index a different entry in the
table. This means that you should have 8 entries loaded in the cache by the
hjb_sign_data() function.

Unfortunately, while simple to understand, it is trickier to perform correctly
since you will run a race against the prefetcher which tries to optimize your
memory accesses loading for you in the caches data you did not request (yet).

### FLUSH + RELOAD v.2

This approach is a bit trickier to understand but yields better results.
Here instead of flushing the entire table you pick a single entry
(e.g., table[0]) and you only flush this one while modifying the input.

For every byte in the key you need to pass all the 256 possible byte values
for your plaintext (i.e., in[8]). Then, since also the other 7 bytes in the key
will load entries from the table the trick is to rely on statistical analysis
while randomizing the other values.

That is:

```
for (i in 0..8) {
	for (val in 0..256) {
		in[i] = val;
		for (round in 0..10K) {
			in[other_bits] = rand()%256;
			clflush(table[0]);
			hjb_encrypt(...);
			if (time(table[0]) < CACHED_T)
				results[i]++;
		}
	check_probability();
	}
}
```

## Stage 2: EVICT + RELOAD

Once you have F+R working we ask you to abandon the clflush instruction in
favor of cache eviction to understand the struggle of cache attacks run from
environments where you don't have the privilege to run your own asm
instructions (e.g., JavaScript, network-based attacks).

What you need to do here is to perform cache eviction. Caches have quite
complex architectures nowadays. Hence you're not required to build
sophisticated eviction strategies but simply fill up the cache with random junk
data.

More specifically, if you want to evict the first cache line in a 4K page, you
can achieve this by accessing the first cache line in a sufficient amount of 4K
pages.

Apart from this detail the attack should work as per Stage #1.

## Stage 3: Hardened Crypto (Bonus)

Herbert realized is crypto algorithm was too weak so he decided to implement a
better algorithms. Needless to say, he failed again.

He tried to replicate a multi-round block encryption like AES and realized his
mistake regarding his cache optimization.
Now his algorithm has 2 tables (one for each round) with 64-bit entries. This
means that every cacheline can store up to 8 table entries making it impossible
to fully reveal the key from a single table.
Luckily for you Herbert is using another table that perfectly fits the occasion.

HINT: The encryption algorithm Herbert wrote uses two lookup tables. The first
table uses the higher four bits of each key byte, while the second table uses
the lower four. If you can leak the cache lines used by both tables for each
key byte, you should therefore be able to recover each full key byte.

To enable the hardened version, you have to run the Makefile as follows:

```
CFLAGS="-DHARDENED" make
```

# Tips

You can run your attack program as follows:

```
LD_LIBRARY_PATH="$LD_LIBRARY_PATH:." ./attack
```

In case you want to change the key you want to leak, you can run the following:

```
CFLAGS=-DSECRET make
```

# Deliverable

You're required to submit the source of a program that once compiled together
with the hjbcrypt library is able to retrieve the key defined in the file.
Without any preprocessor defines, you should run against the non-hardened
version of the library and perform the FLUSH + RELOAD attack.
In case you implement EVICT + RELOAD, make sure we can enable it by specifying
-DEVICT.
For the hardened version, we should be able to enable your attack simply by
specifying -DHARDENED.

Since we are dealing with potential hackers, don't try to tamper with the
library. We will run our own version during the grading session ;).

## Deadline

You're required to submit before Tuesday Nov 6, 23:59.
Every late day causes 1 penalty point on the grade (max. delay of 3 days).

## Grades

 8: (Stage 1) You managed to recover the key using F+R
10: (Stage 2) You managed to recover the key using E+R
12: (Stage 3) You broke the hardened crypto
