# user_agent requires /etc/protocols, which is provided by netbase.
# https://github.com/jruby/jruby/issues/3955
if [ ! -f "/etc/protocols" ]; then
  if [ $(command -v apt-get) ]; then
    echo "installing netbase with apt-get"
    sudo apt-get install -y netbase
  else
    echo "installing netbase with yum"
    sudo yum install -y netbase
  fi
fi