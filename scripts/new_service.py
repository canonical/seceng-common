#!/usr/bin/env python3

import argparse
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

CONTROL_ENTRY_TEMPLATE = """
Package: {name}
Architecture: all
Multi-Arch: foreign
Depends:
 ${{misc:Depends}},
 adduser,
 bash,
 seceng-common
Description: [seceng] {name}
"""

def update_debian_control(project_directory, name):
    control_path = project_directory / 'debian' / 'control'
    if not control_path.exists():
        print(f"Warning: {control_path} not found. Skipping control entry.")
        return

    with open(control_path, 'r') as f:
        content = f.read()

    if f'Package: {name}' in content:
        print(f"Entry for {name} already exists in debian/control. Skipping.")
        return

    print(f"Adding entry for {name} to debian/control...")
    entry = CONTROL_ENTRY_TEMPLATE.format(name=name)
    with open(control_path, 'a') as f:
        f.write(entry)

def main():
    parser = argparse.ArgumentParser(description="Import a project to the service.")
    parser.add_argument("--home", help="home directory. Default: /var/lib/[project_name]")
    parser.add_argument("type", choices=["data", "notification"], help="service type.")
    parser.add_argument("name", help="service name.")
    args = parser.parse_args()

    config_data = {
            'name': args.name,
            'home': args.home if args.home else args.name,
            }

    script_path = Path(__file__).parent.resolve()
    repo_root = script_path.parent.parent
    skel_directory = script_path / 'skel'

    project_name = f"seceng-{args.type if args.type == 'data' else 'notifications'}"
    project_directory = repo_root / project_name

    for file_path in skel_directory.rglob('*'):
        if not file_path.is_file():
            continue

        rendered_config = ""
        # Setup template
        if file_path.suffix == '.j2':
            env = Environment(loader=FileSystemLoader(file_path.parent))
            template = env.get_template(file_path.name)
            rendered_config = template.render(config_data)
            extension = ""
        else:
            with open(file_path, 'r') as f:
                rendered_config = f.read()
            extension = file_path.suffix

        # Set the destination file and path
        relative_path = file_path.relative_to(skel_directory)
        destination_file = Path(str(relative_path).replace('new_service', config_data['name']))
        if file_path.suffix == '.j2':
            destination_file = destination_file.with_suffix(extension)

        destination_path = project_directory / destination_file

        # Create directories if necessary
        destination_path.parent.mkdir(parents=True, exist_ok=True)

        # Generate file
        if destination_path.exists():
            print(f'Skipping {destination_file}, file exists...')
        else:
            print(f'Generating {destination_file}...')
            with open(destination_path, 'w') as config_file:
                config_file.write(rendered_config)

    update_debian_control(project_directory, args.name)

    print("\nNow check all generated files and fill/change it accordingly")

if __name__ == "__main__":
    main()
