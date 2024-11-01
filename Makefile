# Variables
CC = gcc
CFLAGS = -Wall -Wextra -Werror
TARGET = response

# Liste des fichiers source et des fichiers objets
SRC = utiles.c aes-128_enc.c response.c
OBJ = $(SRC:.c=.o)

# Règle par défaut : compiler l'exécutable
all: $(TARGET)

# Règle pour compiler l'exécutable
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

# Règle pour compiler les fichiers .o à partir des fichiers .c
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers objets et de l'exécutable
clean:
	rm -f $(OBJ) $(TARGET)

# Nettoyage complet
mrproper: clean

# Commande pour lancer l'exécutable
run: $(TARGET)
	./$(TARGET)
