#! /bin/sh

set -e 
doxygen Doxyfile
cp a/html/structbatadv__priv__coll__graph.dot batpriv.dot
sed -i 's/Node1 \[/Node1 [rank=source,/' batpriv.dot
sed -i 's/style="dashed",label=" bat_priv"/style="dotted",label=" bat_priv"/' batpriv.dot

dot -Gsplines=true -Gsep="+25,25" -Goverlap=scalexy -Gnodesep=0.6 batpriv.dot -Tpng -o batpriv.png
