import React, { Component } from 'react';
import apiClient from '../api/Api';
import TrustedFilterList from '../components/Filters/TrustedFilterList';
import Loading from '../components/ui/Loading';

interface ListState {
    list: string[];
    loading: boolean;
    saved: boolean;
    error: string;
}

class DomainBlacklist extends Component<Record<string, never>, ListState> {
    state: ListState = {
        list: [],
        loading: true,
        saved: false,
        error: '',
    };

    componentDidMount() {
        this.loadList();
    }

    loadList = async () => {
        try {
            const resp = await apiClient.getDomainBlacklist();
            this.setState({ list: resp.list || [], loading: false });
        } catch {
            this.setState({ loading: false, error: 'Failed to load domain blacklist' });
        }
    };

    handleSave = async (lines: string[]) => {
        this.setState({ saved: false, error: '' });
        try {
            await apiClient.setDomainBlacklist({ list: lines, append: false });
            this.setState({ list: lines, saved: true });
        } catch {
            this.setState({ error: 'Failed to save domain blacklist' });
        }
    };

    handleAppend = async (lines: string[]) => {
        this.setState({ saved: false, error: '' });
        try {
            await apiClient.setDomainBlacklist({ list: lines, append: true });
            const resp = await apiClient.getDomainBlacklist();
            this.setState({ list: resp.list || [], saved: true });
        } catch {
            this.setState({ error: 'Failed to append domain blacklist' });
        }
    };

    render() {
        const { list, loading, saved, error } = this.state;
        if (loading) {
            return <Loading />;
        }
        return (
            <>
                {saved && (
                    <div className="alert alert-success alert-dismissible" role="alert">
                        Domain blacklist saved successfully
                    </div>
                )}
                {error && (
                    <div className="alert alert-danger alert-dismissible" role="alert">
                        {error}
                    </div>
                )}
                <TrustedFilterList
                    title="domain_blacklist_title"
                    subtitle="domain_blacklist_desc"
                    placeholder="domain_blacklist_placeholder"
                    list={list}
                    onSave={this.handleSave}
                    onAppend={this.handleAppend}
                />
            </>
        );
    }
}

export default DomainBlacklist;
