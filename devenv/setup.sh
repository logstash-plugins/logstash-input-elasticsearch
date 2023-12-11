#!/bin/sh

# permanently change shell to zsh for codespace user
sudo chsh --shell /bin/zsh "$USER"

sudo apt-get update --fix-missing -y

# Install JRuby
wget -q https://repo1.maven.org/maven2/org/jruby/jruby-dist/9.4.5.0/jruby-dist-9.4.5.0-bin.tar.gz
sudo tar -xzvf  jruby-dist-9.4.5.0-bin.tar.gz -C /usr/share/
sudo rm jruby-dist-9.4.5.0-bin.tar.gz

export PATH=/usr/share/jruby-9.4.5.0/bin:$PATH

# Install the Bundler gem
/usr/share/jruby-9.4.5.0/bin/jruby -S gem install bundler

# Install Logstash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update && sudo apt-get install logstash

# make the directory writable by user
sudo chown -R "$USER" /usr/share/logstash

cd /usr/share/logstash/

# Update dependencies
bundle install

{
    echo export PATH=/usr/share/jruby-9.4.5.0/bin:$PATH
    echo export ELASTIC_SEARCH_ENDPOINT="https://es-unified-telemetry.austinrdc.dev"
    echo export ELASTIC_SEARCH_TARGET_INDEX="filtered_xlens_machinesummary_filtered_raw_hourly-*"
} > ~/.local-env

echo 'source ~/.local-env' >> ~/.zshrc
echo 'source ~/.local-env' >> ~/.bashrc