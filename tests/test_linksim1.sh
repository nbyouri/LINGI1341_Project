#!/bin/bash

# cleanup d'un test précédent
rm -f received_file input_file

# Fichier au contenu aléatoire de 10000 octets
dd if=/dev/urandom of=input_file bs=1 count=10000 &> /dev/null

./link_sim -p 1341 -P 2456 -c 10 -l 10 -d 50  -e 10 -j 10 -r &> link.log &
link_pid=$!

# On lance le receiver et capture sa sortie standard
./receiver -f received_file :: 2456  2> receiver.log &
receiver_pid=$!

cleanup()
{
    kill -9 $receiver_pid
    kill -9 $link_pid
    exit 0
}
trap cleanup SIGINT  # Kill les process en arrière plan en cas de ^-C

sleep 1 # On attend que le receiver se soit bien lance
# On démarre le transfert
if ! ./sender ::1 1341 < input_file 2> sender.log ; then
  echo "Crash du sender!"
  cat sender.log
  err=1  # On enregistre l'erreur
fi

sleep 5 # On attend 5 seconde que le receiver finisse

if ! wait $receiver_pid ; then
    echo "Le receiver ne s'est pas arrete"
    kill -9 $receiver_pid
    err=1
else
    if kill -0 $receiver_pid &> /dev/null ; then
        echo "Crash du receiver!"
        cat receiver.log
        err=1
    fi
fi

# On arrête le simulateur de lien
kill -9 $link_pid &> /dev/null

# On vérifie que le transfert s'est bien déroulé
if [[ "$(md5sum input_file | awk '{print $1}')" != "$(md5sum received_file | awk '{print $1}')" ]]; then
  echo "Le transfert a corrompu le fichier!"
  echo "Diff binaire des deux fichiers: (attendu vs produit)"
  diff -C 9 <(od -Ax -t x1z input_file) <(od -Ax -t x1z received_file)
  exit 1
else
  echo "Le transfert est réussi!"
  exit ${err:-0}  # En cas d'erreurs avant, on renvoie le code d'erreur
fi
