# Copyright (c) 2023 Thomas Durey

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from .base import BaseClient, DefaultEndpointMixin


class Groupments(DefaultEndpointMixin, BaseClient):
    """Create and manage groupments

    Tabs :

    - rights : get rights of the current user

    Usage :

    >>> groupments_client = Groupments()
    >>> # Get rights
    >>> groupments_client.get_tab(5, 'rights')
    >>> # Get all groupments
    >>> groupments_client.all()
    >>> # Get a groupment
    >>> groupments_client.get(5)
    >>> # Create a groupment
    >>> data = {...}  # See BoondManager documentation
    >>> groupments_client.post(data=data)
    >>> # Update a groupment
    >>> data = {...}  # See BoondManager documentation
    >>> groupments_client.put(5, data=data)
    >>> # Delete a groupment
    >>> groupments_client.delete(5)
    >>> # Get default values
    >>> groupments_client.get_default()
    """
    allowed_methods = ['POST', 'GET', 'PUT', 'DELETE']
    list_uri = '/groupments'
    single_uri = '/groupments/{}'
    tabs = ['rights']
