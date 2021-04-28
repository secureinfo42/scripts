#!/bin/bash
APP="$(basename $0)"
SYMBOLS_DIC="/usr/local/share/str-rand/symbols.dat"



#
# Need help ?
#
function usage
{
  echo "
Usage: $APP [-0|-a|-A|-b|-n|-x|-X|-y|-s|-S|-j|+A] <length>

Generate random string from /dev/urandom, using \`tr\` and \`head\`:
  -0 : 0-1
  -n : 0-9
  -l : a-z
  -L : A-Z
  -a : a-z0-9
  -A : A-Z0-9
  -C : zrtpqsdfghjklmwxcvbn                 (consons)
  -V : aeyuio                               (vowels)
  -w : consons/vowels                       (word)
  -b : a-zA-Z0-9                            (base62)
  -B : a-zA-Z0-9/=                          (base64)
  -p : a-zA-Z0-9!@#$%^&*()
  -P : A-Za-z0-9-_=+%
  -x : 0-9a-f                               (hexa lowercase)
  -X : 0-9A-F                               (hexa uppercase)
  -u : UUID generator                       (lowercase)
  -U : UUID generator
  -y : 0-9A-Fa-f
  -s : A-Za-z0-9&\"()[]{}-_=+:/;.,?$*%<>@#
  -g : A-Za-z1-9&()[]{}-_=+:/;.,?%<>@#      (no ambigous chars)
  -R : \\\\x00 -> \\\\xFF                         (all bytes)

Generate random string from very special symbols:
  -S : A-Za-z0-9æ‡‹Çœ¬÷≠…∞≈ºÇ

Generate random string from emoji:
  -j : 💑👍👎👂👀👃👅👄

Generate random string from emoji, symbols and all readable chars:
  +A : A-Za-z0-9_@#%&*_\-+:;,.æ‡‹Çœ¬÷≠…∞≈ºÇ🐻🌏😎

"
exit 0
}



#
# Generate with very special symbols
#
generate_from_all()
{
  len=$1
  source $SYMBOLS_DIC
  for i in $(seq 1 $len); do
    R=$((RANDOM%3))
    [ $R -eq 0 ] && printf "${ji[ $RANDOM%${#ji[@]} ]}"
    [ $R -eq 1 ] && printf "${ab[ $RANDOM%${#ab[@]} ]}"
    [ $R -eq 2 ] && printf "${sy[ $RANDOM%${#sy[@]} ]}"
  done
}



#
# Generate with very special symbols
#
generate_from_emoji()
{
  len=$1
  source $SYMBOLS_DIC
  for i in $(seq 1 $len); do
    R=$((RANDOM%2))
    [ $R -eq 0 ] && printf "${ab[ $RANDOM%${#ab[@]} ]}"
    [ $R -eq 1 ] && printf "${ji[ $RANDOM%${#ji[@]} ]}"
  done
}



#
# Generate with very special symbols
#
generate_special_symbols()
{
  len=$1
  source $SYMBOLS_DIC
  for i in $(seq 1 $len); do
    R=$((RANDOM%2))
    [ $R -eq 0 ] && printf "${ab[ $RANDOM%${#ab[@]} ]}"
    [ $R -eq 1 ] && printf "${sy[ $RANDOM%${#sy[@]} ]}"
  done
}


#
# Generate word (1 conson + 1 vowel)
#
_generate()
{
  ab="$1"
  len="$2"
  dd if=/dev/urandom | tr -dc "$ab" | head -c $len
}


#
# Generate word (1 conson + 1 vowel)
#
generate_uuid()
{
  # 4AA898DE-46AF-4DA4-947A-EE62875CFD93
  p1="$(_generate "0-9A-F" 8)"
  p2="$(_generate "0-9A-F" 4)"
  p3="$(_generate "0-9A-F" 4)"
  p4="$(_generate "0-9A-F" 4)"
  p5="$(_generate "0-9A-F" 12)"
  printf -- "$p1-$p2-$p3-$p4-$p5" 
}



#
# Generate word (1 conson + 1 vowel)
#
generate_word()
{
	len=$1
	s=""
	for i in $(seq 1 $len); do
		if [ "$((i%2))" = "0" ]; then
			ab="aeyuio"
		else
			ab="zrtpqsdfghjklmwxcvbn"
		fi
		s=$s$(dd if=/dev/urandom | tr -dc "$ab" | head -c 1)
	done
	printf $s
}


#
# Minimal args
#
[ $# -gt 2 ]    && usage
[ "$1" = "-h" ] && usage



#
# Default values
#
ab='a-zA-Z0-9'
len=8



#
# If args passed
#
if [ $# -ge 1 ]; then
	ab=""
	case "$1" in
		"-l") ab='a-z'       ;;
		"-L") ab='A-Z'       ;;
		"-0") ab='0-1'       ;;
		"-n") ab='0-9'       ;;
		"-a") ab='a-z0-9'    ;;
		"-A") ab='A-Z0-9'    ;;
		"-b") ab='A-Za-z0-9' ;;
		"-B") ab='A-Za-z0-9/='           ;;
		"-p") ab='A-Za-z0-9!@#$^&*%()'   ;;
		"-P") ab='A-Za-z0-9-_=+%'        ;;
		"-C") ab='zrtpqsdfghjklmwxcvbn'  ;;
		"-V") ab='aeiouy'    ;;
    "-w") ab='word'      ;;
		"-x") ab='a-f0-9'    ;;
		"-X") ab='A-F0-9'    ;;
		"-y") ab='a-fA-F0-9' ;;
		"-s") ab='A-Za-z0-9&"()[]{}_=+:/;.,?$*%<>@#' ;;
		"-g") ab='A-Za-z1-9&()[]{}_=+:/;.,?%<>@#'    ;;
		"+A") ab='[all]'        ;;
		"-U") ab='[uuid]'       ;;
    "-u") ab='[uuid_lower]' ;;
    "-R") ab='[bytes]'      ;;
		"-j") ab='[emoji]'      ;;
		"-S") ab='[symbols]'    ;;
       *) ab='a-zA-Z0-9' ; len=$1 ;;
	esac
	if [ $# -eq 2 ]; then
		if [ "$ab" != "" ]; then
			len=$2
		else
			usage 1
		fi
	fi
fi


#
# Show results
#
case $ab in
     "[emoji]") generate_from_emoji $len                         ;;
   "[symbols]") generate_special_symbols $len                    ;;
       "[all]") generate_from_all $len                           ;;
      "[uuid]") generate_uuid                                    ;;
"[uuid_lower]") generate_uuid|tr "A-F" "a-f"                     ;;
     "[bytes]") dd if=/dev/urandom | head -c $len                ;;
        "word") generate_word $len                               ;;
             *) _generate "$ab" "$len"                           ;;
esac
