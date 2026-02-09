#!/usr/bin/env python3

import argparse
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

TO_DO_TEXT = '''
To Do:
 - Add entry in debian/control;
 - Check all generated files and fill/change it accordingly;
'''

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

    for file_path in skel_directory.rglob(f'*.j2'):
        # Setup template
        env = Environment(loader=FileSystemLoader(file_path.parent))
        template = env.get_template(file_path.name)
        rendered_config = template.render(config_data)

        # Set the destination file and path
        destination_file = Path(str(file_path.relative_to(skel_directory)).replace('new_service', config_data['name'])).with_suffix('')
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

    print(TO_DO_TEXT)

if __name__ == "__main__":
    main()
