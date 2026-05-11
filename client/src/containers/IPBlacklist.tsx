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

class IPBlacklist extends Component<Record<string, never>, ListState> {
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
            const resp = await apiClient.getIPBlacklist();
            this.setState({ list: resp.list || [], loading: false });
        } catch {
            this.setState({ loading: false, error: 'Failed to load IP blacklist' });
        }
    };

    handleSave = async (lines: string[]) => {
        this.setState({ saved: false, error: '' });
        try {
            await apiClient.setIPBlacklist({ list: lines, append: false });
            this.setState({ list: lines, saved: true });
        } catch {
            this.setState({ error: 'Failed to save IP blacklist' });
        }
    };

    handleAppend = async (lines: string[]) => {
        this.setState({ saved: false, error: '' });
        try {
            await apiClient.setIPBlacklist({ list: lines, append: true });
            const resp = await apiClient.getIPBlacklist();
            this.setState({ list: resp.list || [], saved: true });
        } catch {
            this.setState({ error: 'Failed to append IP blacklist' });
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
                        IP blacklist saved successfully
                    </div>
                )}
                {error && (
                    <div className="alert alert-danger alert-dismissible" role="alert">
                        {error}
                    </div>
                )}
                <TrustedFilterList
                    title="ip_blacklist_title"
                    subtitle="ip_blacklist_desc"
                    placeholder="ip_blacklist_placeholder"
                    list={list}
                    onSave={this.handleSave}
                    onAppend={this.handleAppend}
                />
            </>
        );
    }
}

export default IPBlacklist;
