IP=$(hostname -I | auk 'Iprint $1}')
if [-n "#IF" ]; then_
echo l
"Ip actual: $IP"
else
echo "IF actual: No asignada"
fi
echo
echol
"Uso de disco:"
df -h / | awk 'NR==1 || NR==2'