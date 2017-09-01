FUZZPROGS = curl_fuzzer
FUZZLIBS = libstandaloneengine.a

curl_fuzzer_SOURCES = curl_fuzzer.c
curl_fuzzer_CFLAGS = $(AM_CFLAGS)

libstandaloneengine_a_SOURCES = standalone_fuzz_target_runner.c
libstandaloneengine_a_CFLAGS = $(AM_CFLAGS)

# Some more targets.
zip:
	zip -q -r curl_fuzzer_seed_corpus.zip curl_fuzz_data

check: all
	./curl_fuzzer curl_fuzz_data/*