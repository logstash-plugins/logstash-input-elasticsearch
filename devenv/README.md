# Logstash Elasticsearch InputPlugin

This is a suplement document to ~/README.md.

## Developing

### 1. Plugin Developement and Testing

Check out ~/devenv/setup.sh file for development enviroment set up.

#### Code

- Install dependencies
```sh
./devenv/setup.sh
```

#### Test

- Run tests

```sh
export PATH=/usr/share/jruby-9.4.5.0/bin:$PATH

cd /usr/share/logstash
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in a local Logstash clone

- Edit Logstash `Gemfile` and add the local plugin path, for example:
```ruby
gem "logstash-input-elasticsearch", :path => "/your/local/logstash-input-elasticsearch"
```
- Install plugin
```sh
bin/logstash-plugin install --no-verify
```
- Run Logstash with your plugin
```sh
bin/logstash -e 'input {logstash-input-elasticsearch {}}'
```
At this point any modifications to the plugin code will be applied to this local Logstash setup. After modifying the plugin, simply rerun Logstash.

#### 2.2 Run in an installed Logstash

You can use the same **2.1** method to run your plugin in an installed Logstash by editing its `Gemfile` and pointing the `:path` to your local plugin development directory or you can build the gem and install it using:

- Build your plugin gem
```sh
gem build logstash-input-elasticsearch.gemspec
```
- Install the plugin from the Logstash home
```sh
bin/logstash-plugin install --no-verify
```
- Start Logstash and proceed to test the plugin


## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elastic/logstash/blob/master/CONTRIBUTING.md) file.
