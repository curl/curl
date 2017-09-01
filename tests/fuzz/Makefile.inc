FUZZPROGS = curl_fuzzer
FUZZLIBS = libstandaloneengine.a

curl_fuzzer_SOURCES = curl_fuzzer.cc
curl_fuzzer_CXXFLAGS = $(AM_CXXFLAGS)

libstandaloneengine_a_SOURCES = standalone_fuzz_target_runner.cc
libstandaloneengine_a_CXXFLAGS = $(AM_CXXFLAGS)

# Some more targets.
zip:
	zip -q -r curl_fuzzer_seed_corpus.zip curl_fuzz_data

check: all
	./curl_fuzzer curl_fuzz_data/*
