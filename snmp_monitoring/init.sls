include:
  - zookeeper_monitoring
  - mongodb_monitoring
  - cg_monitoring

install_required_packages_snmp:
  pkg:
    - installed
    - pkgs:
       - python27-virtualenv
       - libffi-devel
       - libsmi
       - libsmi-devel

create_venv_directory_snmp:
  file.directory:
    - name: /opt/spot/snmp_monitoring/
    - makedirs: True

create_virtual_env_snmp:
  virtualenv.managed:
    - name: /opt/spot/snmp_monitoring/venv
    - venv_bin: /opt/python-2.7.3/bin/virtualenv-2.7
    - system_site_packages: False
    - require:
      - pkg: install_required_packages_snmp

install_snimpy_to_virtualenv:
  cmd.run:
    - name: /opt/spot/snmp_monitoring/venv/bin/easy_install http://<Pypi server>/pypi/3rdparty/python/simple/snimpy/snimpy-0.8.2.tar.gz
    - unless: ls /opt/spot/snmp_monitoring/venv/lib/python2.7/site-packages/snimpy-0.8.2*
    - requires:
      - virtualenv.managed: create_virtual_env_snmp

install_requests_to_virtualenv_snmp:
  cmd.run:
    - name: /opt/spot/snmp_monitoring/venv/bin/easy_install http://<Pypi server>/pypi/3rdparty/python/simple/requests/requests-2.0.1.tar.gz
    - unless: ls /opt/spot/snmp_monitoring/venv/lib/python2.7/site-packages/requests-2.0.1*
    - requires:
      - virtualenv.managed: create_virtual_env_snmp

install_pygerduty_to_virtualenv_snmp:
  cmd.run:
    - name: /opt/spot/snmp_monitoring/venv/bin/easy_install http://<Pypi server>/pypi/3rdparty/python/pygerduty-0.23-py2.7.egg
    - unless: ls /opt/spot/snmp_monitoring/venv/lib/python2.7/site-packages/pygerduty-0.23*
    - requires:
      - virtualenv.managed: create_virtual_env_snmp

install_pepper_to_virtualenv:
  cmd.run:
    - name: /opt/spot/snmp_monitoring/venv/bin/easy_install http://<Pypi server>/pypi/3rdparty/python/simple/salt-pepper/salt-pepper-0.2.0.tar.gz
    - unless: ls /opt/spot/snmp_monitoring/venv/lib/python2.7/site-packages/salt_pepper-*
    - requires:
      - virtualenv.managed: create_virtual_env_snmp

copy_snmp_monitoring:
  file.managed:
    - name: /opt/spot/snmp_monitoring/check_hp.py
    - source: salt://snmp_monitoring/check_hp.py
    - makedirs: True
    - template: jinja
    - require:
      - pkg: install_required_packages_snmp
      - file: create_venv_directory_snmp
      - virtualenv.managed: create_virtual_env_snmp
      - cmd: install_snimpy_to_virtualenv
      - cmd: install_requests_to_virtualenv_snmp

copy_logstash_config:
  file.managed:
    - name: /etc/logstash/conf.d/shipper.conf
    - source: salt://snmp_monitoring/shipper.conf
    - makedirs: True
    - template: jinja
    - require:
      - file: copy_snmp_monitoring

check_logstash:
  service:
    - running
    - enable: True
    - name: logstash
    - require:
      - file: copy_logstash_config
    - watch:
      - file: copy_logstash_config

copy_mibs:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/mibs
    - source: salt://snmp_monitoring/mibs
    - require:
       - file: copy_snmp_monitoring

copy_cisco:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/check_cisco
    - template: jinja
    - source: salt://snmp_monitoring/check_cisco
    - require:
       - file: copy_snmp_monitoring
            
copy_arista:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/check_arista
    - template: jinja
    - source: salt://snmp_monitoring/check_arista
    - require:
       - file: copy_snmp_monitoring

copy_hp_blades:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/check_blades
    - source: salt://snmp_monitoring/check_blades
    - require:
       - file: copy_snmp_monitoring

copy_sm_raid:
  file.managed:
    - name: /opt/spot/snmp_monitoring/check_sm_raid/check_sm_raid.py
    - template: jinja
    - source: salt://snmp_monitoring/check_sm_raid/check_sm_raid.py.jinja
    - makedirs: True    
    - template: jinja
    - require:
       - file: copy_snmp_monitoring

copy_datadomain:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/check_datadomain
    - template: jinja
    - source: salt://snmp_monitoring/check_datadomain
    - require:
       - file: copy_snmp_monitoring

copy_riverbed:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/check_riverbed
    - template: jinja
    - source: salt://snmp_monitoring/check_riverbed
    - require:
       - file: copy_snmp_monitoring

copy_npulse:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/check_npulse
    - source: salt://snmp_monitoring/check_npulse
    - require:
       - file: copy_snmp_monitoring

copy_brocade:
  file.recurse:
    - name: /opt/spot/snmp_monitoring/check_brocade
    - template: jinja
    - source: salt://snmp_monitoring/check_brocade
    - require:
       - file: copy_snmp_monitoring

set_grain_snmp:
  grains.present:
    - name: it_application
    - value: snmp_monitoring
    - require: 
      - file: copy_mibs

schedule_script_every_30_min_snmp:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_hp.py
    - user: root
    - minute: '*/30'
    - require:
      - file: copy_mibs

schedule_script_every_hour:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_sm_raid/check_sm_raid.py
    - user: root
    - minute: '0'
    - require:
      - file: copy_sm_raid

{% if grains['master'] == 'saltProduction' %}

schedule_cisco_every_30_min:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_cisco/check_cisco_hw.py
    - user: root
    - minute: '*/30'
    - require:
      - file: copy_cisco

schedule_arista_every_30_min:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_arista/check_arista_hw.py
    - user: root
    - minute: '*/30'
    - require:
      - file: copy_arista

schedule_hp_blades_every_30_min:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_blades/check_hp_blade.py
    - user: root
    - minute: '0'
    - require:
      - file: copy_hp_blades

schedule_datadomain_every_day:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_datadomain/check_datadomain.py
    - user: root
    - minute: '55'
    - hour: '12'
    - require:
      - file: copy_datadomain

schedule_riverbed_every_day:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_riverbed/check_riverbed.py
    - user: root
    - minute: '50'
    - hour: '12'
    - require:
      - file: copy_riverbed

schedule_npulse_every_35_min:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_npulse/check_npulse.py
    - user: root
    - minute: '*/35'
    - require:
      - file: copy_npulse

schedule_brocade_every_40_min:
  cron:
    - present
    - name: /opt/spot/snmp_monitoring/venv/bin/{{ pillar['os_pillars']['py_binary'] }} /opt/spot/snmp_monitoring/check_brocade/check_brocade.py
    - user: root
    - minute: '*/40'
    - require:
      - file: copy_brocade

{% endif %}
