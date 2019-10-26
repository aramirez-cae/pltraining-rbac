rbac_role { 'Viewers':
  ensure      => 'present',
  description => 'Viewers',
  groups      => ['developers'],
  permissions => [
  {
    'object_type' => 'nodes',
    'action' => 'view_data',
    'instance' => '*'
  },
  {
    'object_type' => 'console_page',
    'action' => 'view',
    'instance' => '*'
  }],
  users       => ['Testy Test'],
}
