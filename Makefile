all:
	$(CC) -O3 -Wall -l gnutls quickcert.c -o quickcert
clean:
	rm quickcert
